// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What delivering a peer's message costs on an open table and on a closed one
//! (`docs/closed-key-set.md`, phase 3b), measured in one process and one condition: the same
//! subscribers, the same keys, the same samples, and only the gate differs.
//!
//! Two shapes of traffic:
//!
//! * `rotate`: the messages cycle through every key of the fixture (18 keys, 8 subscribers, several
//!   of them wildcards). On an open table this is mostly the match memory's misses, since the memory
//!   holds a few keys at a time; it is what a node that hears many keys sees.
//! * `repeat`: one key, again and again. On an open table the memory answers every message after the
//!   first; it is what a node that hears one stream sees, and the case the memory was built for.
//!
//! and the heap allocations per message, which are exact: the same number on every host and every
//! run. The match memory allocates when it remembers a key, so the allocations of `rotate` on an
//! open table are the memory's writes.
//!
//! NOTHING HERE IS A GATE ON TIME. A time is PRINTED and read by a person on a quiet host, in a
//! release build, on the build machine:
//!
//! ```text
//! cargo test --release -p wz-session-core --test key_set_cost -- --nocapture
//! WZ_LIMIT_MATCH_MEMO_SLOTS=0 cargo test --release ... (the same, with the memory left out)
//! WZ_KEYSET_N=2000000 ... (the same, with more messages)
//! ```
//!
//! What IS asserted is that both deliveries fired the same subscribers the same number of times, so a
//! delivery that dropped its work cannot read as a fast one.
#![cfg(all(
    feature = "alloc",
    feature = "keyexpr-wildcard-single",
    feature = "keyexpr-wildcard-double",
    feature = "keyexpr-dollar-star"
))]

// The generated table is a module of its own (`key_set`) that a file includes, as a node's
// generated `declared.rs` does.
mod fixture {
    include!("key_set_data/fixture.rs");
}

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use fixture::key_set::{CATALOGUE, DECLARED};
use wz_session_core::key_catalogue::EntityKind;
use wz_session_core::key_gate::KeyGate;
use wz_session_core::locality::Locality;
use wz_session_core::pubsub::SubscriberTable;
use wz_session_core::sample::Sample;
use wz_session_core::sink::{SampleSink, SampleView};

/// The system allocator, counting what this thread asks it for.
struct Counting;

std::thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn allocations_here() -> usize {
    ALLOCATIONS.with(Cell::get)
}

fn count_one() {
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

/// A sink that counts its deliveries and does nothing else.
struct Count(Rc<Cell<usize>>);

impl SampleSink for Count {
    fn deliver(&mut self, _sample: &dyn SampleView) {
        self.0.set(self.0.get() + 1);
    }
}

fn table(closed: bool, delivered: &Rc<Cell<usize>>) -> SubscriberTable<Count> {
    let mut table: SubscriberTable<Count> = SubscriberTable::with_sink_backing();
    if closed {
        table.set_key_gate(KeyGate::closed(&CATALOGUE));
    }
    for (kind, pattern) in DECLARED.iter() {
        if *kind == EntityKind::Subscriber {
            table
                .register_sink(pattern, Locality::Any, Count(Rc::clone(delivered)))
                .expect("room for the fixture's subscribers");
        }
    }
    table
}

fn samples() -> Vec<Sample> {
    (0..CATALOGUE.key_count())
        .map(|index| {
            let key = wz_session_core::key_catalogue::KeyId::new(index as u16);
            Sample::new_put(CATALOGUE.text(key), vec![0u8; 16])
        })
        .collect()
}

/// What `messages` deliveries of the cycle `order` over `samples` cost: the least time of
/// `rounds` runs, and the allocations of one more run, each per message, and what fired.
fn measure(
    table: &mut SubscriberTable<Count>,
    delivered: &Rc<Cell<usize>>,
    samples: &[Sample],
    order: &[usize],
    messages: usize,
    rounds: usize,
) -> (f64, f64, usize) {
    let run = |table: &mut SubscriberTable<Count>| {
        for number in 0..messages {
            let sample = &samples[order[number % order.len()]];
            table.dispatch_borrowed(sample, true);
        }
    };
    // Warm: the match memory remembers what it is going to remember.
    run(table);
    let mut best = Duration::MAX;
    for _ in 0..rounds {
        let start = Instant::now();
        run(table);
        best = best.min(start.elapsed());
    }
    delivered.set(0);
    let before = allocations_here();
    run(table);
    let allocations = allocations_here() - before;
    (
        best.as_nanos() as f64 / messages as f64,
        allocations as f64 / messages as f64,
        delivered.get(),
    )
}

#[test]
fn what_a_peers_message_costs_on_an_open_table_and_on_a_closed_one() {
    let messages: usize = std::env::var("WZ_KEYSET_N")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(200_000);
    let samples = samples();
    let all: Vec<usize> = (0..samples.len()).collect();
    let one: Vec<usize> = vec![CATALOGUE
        .find_exact("lab/sensor/temp")
        .expect("declared")
        .index()];

    println!(
        "key set cost: {} keys, {} subscribers, {messages} messages a run, memo slots {}",
        CATALOGUE.key_count(),
        DECLARED
            .iter()
            .filter(|(kind, _)| *kind == EntityKind::Subscriber)
            .count(),
        wz_session_core::caps::MATCH_MEMO_SLOTS,
    );
    println!("  traffic   gate     ns/msg   allocs/msg   fired/run");
    for (name, order) in [("rotate", &all), ("repeat", &one)] {
        let mut fired_by_gate = Vec::new();
        for (gate, closed) in [("open", false), ("closed", true)] {
            let delivered = Rc::new(Cell::new(0));
            let mut table = table(closed, &delivered);
            let (nanos, allocations, fired) =
                measure(&mut table, &delivered, &samples, order, messages, 7);
            println!("  {name:<8}  {gate:<6}  {nanos:>7.1}  {allocations:>11.3}  {fired:>10}");
            fired_by_gate.push(fired);
            assert!(fired > 0, "{name} {gate}: nothing was delivered");
        }
        assert_eq!(
            fired_by_gate[0], fired_by_gate[1],
            "{name}: the closed table fired what the open one fired"
        );
    }
}

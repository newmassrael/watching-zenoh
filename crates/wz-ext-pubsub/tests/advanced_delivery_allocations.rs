// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The advanced subscriber's ordering machine hands on a sample it does not keep without
//! allocating: the in-order samples of a sequenced source and the newer samples of a timestamped
//! one, once the source is known. A sample is looked up by its source's fixed identity and handed
//! on as the view it was lent, so nothing of it is copied. The count is the measuring thread's
//! (a counting global allocator), so libtest's own threads move no number; the control shows the
//! window sees what the machine copies when it buffers a sample.
#![cfg(feature = "advanced-recovery")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_ext_pubsub::advanced_subscriber::{Delivery, MissHandlers, State};
use wz_session_core::sample::{Sample, SourceInfo, TimestampHint};

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

/// A machine that counts what it hands on into `heard`; `retransmission` says whether a forward
/// gap is buffered.
fn machine(retransmission: bool, heard: &Arc<AtomicUsize>) -> State {
    let heard = Arc::clone(heard);
    State::new(
        Box::new(move |_delivery: Delivery<'_>| {
            heard.fetch_add(1, Ordering::SeqCst);
        }),
        MissHandlers::default(),
    )
    .with_retransmission(retransmission)
}

/// A put carrying `SourceInfo(zid 0x02, eid 7, sn)`.
fn sequenced(sn: u32) -> Sample {
    let mut sample = Sample::new_put("demo/data", vec![0xA0]);
    sample.source_info = Some(SourceInfo::new(&[0x02], 7, sn));
    sample
}

/// A put carrying a timestamp of the id `0x03` and no source info.
fn timestamped(time: u64) -> Sample {
    let mut sample = Sample::new_put("demo/data", vec![0xB0]);
    sample.timestamp = Some(TimestampHint::new(time, &[0x03]).expect("a one-byte id"));
    sample
}

#[test]
fn in_order_samples_of_a_known_sequenced_source_allocate_nothing() {
    let heard = Arc::new(AtomicUsize::new(0));
    let mut state = machine(false, &heard);
    let samples: Vec<Sample> = (0..9).map(sequenced).collect();
    // The first sample meets the source, which takes its row in the table.
    assert!(state.handle_live(&samples[0], 1).is_none());
    let before = allocations();
    for sample in &samples[1..] {
        assert!(state.handle_live(sample, 1).is_none());
    }
    let during = allocations() - before;
    assert_eq!(heard.load(Ordering::SeqCst), 9, "every sample is handed on");
    assert_eq!(
        during, 0,
        "an in-order sample of a known source allocates nothing"
    );
}

#[test]
fn newer_samples_of_a_known_timestamped_source_allocate_nothing() {
    let heard = Arc::new(AtomicUsize::new(0));
    let mut state = machine(false, &heard);
    let samples: Vec<Sample> = (1..=9).map(timestamped).collect();
    assert!(state.handle_live(&samples[0], 1).is_none());
    let before = allocations();
    for sample in &samples[1..] {
        assert!(state.handle_live(sample, 1).is_none());
    }
    let during = allocations() - before;
    assert_eq!(
        heard.load(Ordering::SeqCst),
        9,
        "every newer sample is handed on"
    );
    assert_eq!(
        during, 0,
        "a newer sample of a known source allocates nothing"
    );
}

/// CONTROL: a sample the machine must keep past the call is copied, and the window counts it.
#[test]
fn a_sample_the_machine_buffers_is_counted() {
    let heard = Arc::new(AtomicUsize::new(0));
    let mut state = machine(true, &heard);
    let (first, after_gap) = (sequenced(0), sequenced(2));
    assert!(state.handle_live(&first, 1).is_none());
    let before = allocations();
    let request = state.handle_live(&after_gap, 1);
    let during = allocations() - before;
    assert!(request.is_some(), "the gap asks for recovery");
    assert_eq!(
        heard.load(Ordering::SeqCst),
        1,
        "the sample past the gap is held"
    );
    assert!(during > 0, "the window sees the copy the buffer keeps");
}

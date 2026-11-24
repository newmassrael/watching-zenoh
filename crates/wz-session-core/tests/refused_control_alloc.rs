// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A participant's receive reads a JOIN and a transport OAM into its slot without the heap, and
//! reads them to the end the observer's decode reads them to.
//!
//! A participant refuses both messages whatever they say, so its read
//! (`parse_inbound_consuming_into`, the session's receive) judges each where it lies and keeps
//! nothing of it: neither an OAM's ZBuf body nor a ZBuf extension of either chain is copied. The
//! observer's decode of the same message (`parse_inbound_consuming`) keeps it whole, and must cost
//! the heap something: that half is the instrument's control, the proof that a zero on the
//! receive's side is a measurement and not a counter that cannot see a `Vec`.
//!
//! Only the allocations of the calling thread are counted.
#![cfg(all(feature = "alloc", feature = "storage-profile"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use wz_codecs::wire_const;
use wz_session_core::inbound::{
    parse_inbound_consuming, parse_inbound_consuming_into, InboundFrame,
};

/// Counts the allocations made BY THE CURRENT THREAD.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a
// thread-local counter bump, which neither allocates nor unwinds.
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

fn allocations_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let before = ALLOCATIONS.with(Cell::get);
    let out = f();
    (out, ALLOCATIONS.with(Cell::get) - before)
}

/// What the receive's read and the observer's decode of `wire` cost the heap, after both are
/// held to reading the whole message as a refused one.
fn costs(wire: &[u8], mid: u8) -> (usize, usize) {
    let mut slot = InboundFrame::Unknown { mid: 0 };
    let (into, into_allocations) =
        allocations_during(|| parse_inbound_consuming_into(wire, &mut slot));
    assert_eq!(into.expect("the receive reads it"), wire.len());
    assert!(
        matches!(slot, InboundFrame::Refused { mid: read } if read == mid),
        "{slot:?}"
    );
    let (decoded, decode_allocations) =
        allocations_during(|| parse_inbound_consuming(wire).map(|(_, used)| used));
    assert_eq!(
        decoded.expect("the observer decodes it"),
        wire.len(),
        "the same extent"
    );
    (into_allocations, decode_allocations)
}

#[test]
fn an_oam_read_into_the_slot_costs_the_heap_nothing() {
    // A ZBuf extension (id 0x2) in the chain, then a ZBuf body.
    let wire = [
        wire_const::T_MID_OAM | wire_const::FLAG_T_Z | 0x40,
        0x01,
        0x42,
        0x02,
        0xAB,
        0xCD,
        0x02,
        0xEE,
        0xFF,
    ];
    let (read, decoded) = costs(&wire, wire_const::T_MID_OAM);
    assert_eq!(read, 0, "the receive's read of the OAM allocated");
    assert!(
        decoded > 0,
        "CONTROL: the observer's decode made no allocation, so a zero proves nothing"
    );
}

#[cfg(feature = "codec-join")]
#[test]
fn a_join_read_into_the_slot_costs_the_heap_nothing() {
    let join = wz_codecs::join::Join {
        version: 0x09,
        cbyte: (3 << 4) | 0x01,
        zid: wz_codecs::Bounded::new(&[0xA0u8, 0xA1, 0xA2, 0xA3] as &[u8]).expect("a zid"),
        s: Some(wz_codecs::join::JoinS {
            sn_res: 0x00,
            batch_size: 0x1000,
        }),
        lease: 10_000,
        next_sn_reliable: 7,
        next_sn_best_effort: 9,
    };
    let mut wire = vec![wire_const::T_MID_JOIN | wire_const::FLAG_T_JOIN_S | wire_const::FLAG_T_Z];
    wire.extend_from_slice(&join.encode_to_vec());
    // The QoS extension (id 0x1, mandatory, a ZBuf) behind the body.
    wire.extend_from_slice(&[0x51, 0x02, 0xAB, 0xCD]);
    let (read, decoded) = costs(&wire, wire_const::T_MID_JOIN);
    assert_eq!(read, 0, "the receive's read of the JOIN allocated");
    assert!(
        decoded > 0,
        "CONTROL: the observer's decode made no allocation, so a zero proves nothing"
    );
}

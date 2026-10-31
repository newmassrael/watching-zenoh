// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multicast JOIN beacon written into an array costs the heap nothing
//! (fixed-memory step S9d), and the `Vec` it used to be written into costs it
//! something.
//!
//! `encode_join` returns an owned `Vec<u8>` (a `with_capacity`, a growing body, a
//! second vector for the QoS extension's body), and the node's multicast loop
//! sends one every beacon interval for as long as it runs. `encode_join_into`
//! writes the same datagram through the codec's sink seam into a buffer the
//! caller holds. This file counts the heap over each, for the shapes the beacon
//! takes (a protocol-default config, a departing one, a QoS group), and requires
//! zero for the sink form and a positive count for the `Vec` form: the second
//! half is the instrument's control, the proof that a zero is a measurement and
//! not a counter that cannot see a vector.
//!
//! Only the allocations of the calling thread are counted.
#![cfg(all(feature = "session-multicast", feature = "codec-join"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use sce_forge_runtime::codec::SliceSink;
use wz_codecs::whatami::WhatAmI;
use wz_session_core::multicast_join::{encode_join, encode_join_into, JOIN_MAX_BYTES};
use wz_session_core::multicast_params::{zid_vec, MulticastParams};
use wz_session_core::session_init_params::{LinkRxConf, TxQueueConf};
use wz_session_core::sn::{mask_from_res, MulticastTxConduits};

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

fn params(batch_size: u16, is_qos: bool) -> MulticastParams {
    MulticastParams {
        whatami: WhatAmI::Peer,
        zid: zid_vec(&[0xab; 8]),
        lease_ms: 10_000,
        join_interval_ms: 2_500,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size,
        is_qos,
        compression: false,
        tx_queue: TxQueueConf::default(),
        link_rx: LinkRxConf::default(),
    }
}

#[test]
fn a_join_beacon_written_into_an_array_costs_the_heap_nothing() {
    let mut wrong: Vec<String> = Vec::new();
    // The protocol-default batch size (the minimal beacon), a departing one (the
    // S optionals), and a QoS group (the per-priority extension).
    for (what, p) in [
        ("protocol defaults", params(8192, false)),
        ("a departing config", params(2048, false)),
        ("a qos group", params(2048, true)),
    ] {
        let mut tx = MulticastTxConduits::new(mask_from_res(p.seq_num_res));
        // SNs that are several VLE bytes wide, so the QoS body is not trivial.
        for _ in 0..300 {
            tx.mint(wz_session_core::qos::Priority::DEFAULT, true);
        }
        let mut slot = [0u8; JOIN_MAX_BYTES];
        let (written, lent) = allocations_during(|| {
            let mut sink = SliceSink::new(&mut slot);
            encode_join_into(&p, &tx, &mut sink).expect("fits its bound");
            sink.position()
        });
        let (owned, owned_allocations) = allocations_during(|| encode_join(&p, &tx));
        println!("{what}: array {lent} allocation(s), Vec {owned_allocations}");
        if slot[..written] != owned[..] {
            wrong.push(format!("{what}: the bytes differ"));
        }
        if lent != 0 {
            wrong.push(format!("{what}: the array form made {lent} allocation(s)"));
        }
        if owned_allocations == 0 {
            wrong.push(format!(
                "{what}: CONTROL, the Vec form made no allocation, so a zero proves nothing"
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

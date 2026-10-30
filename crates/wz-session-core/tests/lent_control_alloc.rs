// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A control message written from the caller's own text costs the heap nothing
//! (fixed-memory step S9d), and the owned builder it mirrors costs it something.
//!
//! The writers of `wz_session_core::lent_control` return the codec's BORROWED view
//! over the caller's `&str`, with its one-entry extension chain inline, and the
//! view is encoded into a buffer the caller holds (here, an array on the stack,
//! which is what the slot a link lends is). This file counts the heap over the
//! whole of that, for every message the module writes: the writer, and the encode
//! into the buffer. Beside it, the same message through its owned builder
//! (`declare_build`, `interest_build`, `response_final_build`) and the owned
//! mirror's own encode, which must cost the heap something: that half is the
//! instrument's control, the proof that a zero on the writer's side is a measurement
//! and not a counter that cannot see a `String` or a `Vec`.
//!
//! Only the allocations of the calling thread are counted, so the other tests of
//! this binary cannot move a number.
//!
//! Compiles with the declaration family and the `ResponseFinal` codec on, the
//! features the writers it counts are gated on.
#![cfg(all(
    feature = "codec-declare",
    feature = "declare-final",
    feature = "codec-response-final"
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use sce_forge_runtime::codec::SliceSink;
use wz_session_core::declare_build as owned;
use wz_session_core::interest_build::{self as owned_interest, InterestKinds};
use wz_session_core::lent_control as lent;
use wz_session_core::queryable_info::QueryableInfo;
use wz_session_core::response_final_build::build_response_final;
use wz_session_core::sample::QosLevel;

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

/// The slot a link would lend, as an array: the widest control message is a
/// few hundred bytes (`Declare::MAX_ENCODED_BYTES` is 612).
const SLOT: usize = 1024;

/// One window: build the writer's value and encode it into a buffer of the
/// caller's own. Returns the bytes written and what the heap saw.
macro_rules! lent_window {
    ($build:expr) => {{
        let mut slot = [0u8; SLOT];
        let (written, allocations) = allocations_during(|| {
            let message = $build;
            let mut sink = SliceSink::new(&mut slot);
            message.encode(&mut sink).expect("fits the slot");
            sink.position()
        });
        (slot[..written].to_vec(), allocations)
    }};
}

/// The same message through its owned builder and the owned mirror's own encode.
macro_rules! owned_window {
    ($build:expr) => {{
        let (bytes, allocations) = allocations_during(|| {
            let message = $build;
            let encoded = message
                .try_as_borrowed()
                .expect("a view")
                .encode_to_vec()
                .expect("the builder's message is encodable");
            encoded
        });
        (bytes, allocations)
    }};
}

/// Count every writer, pair it with its builder, and require: the writer's bytes
/// are the builder's, the writer allocates nothing, the builder allocates
/// something (the control).
macro_rules! pair {
    ($wrong:ident, $name:literal, $lent:expr, $owned:expr) => {{
        let (lent_bytes, lent_allocations) = lent_window!($lent);
        let (owned_bytes, owned_allocations) = owned_window!($owned);
        println!(
            "{}: lent {lent_allocations} allocation(s), owned {owned_allocations}",
            $name
        );
        if lent_bytes != owned_bytes {
            $wrong.push(format!("{}: the bytes differ", $name));
        }
        if lent_allocations != 0 {
            $wrong.push(format!(
                "{}: the writer made {lent_allocations} allocation(s)",
                $name
            ));
        }
        if owned_allocations == 0 {
            $wrong.push(format!(
                "{}: CONTROL, the owned builder made no allocation, so a zero on the writer proves nothing",
                $name
            ));
        }
    }};
}

#[test]
fn every_control_writer_costs_the_heap_nothing_and_its_builder_costs_it_something() {
    let mut wrong: Vec<String> = Vec::new();
    let key = "demo/control/key";
    let info = QueryableInfo::local(true);

    pair!(
        wrong,
        "declare_kexpr",
        lent::declare_kexpr(5, key),
        owned::build_declare_kexpr(5, key).unwrap()
    );
    pair!(
        wrong,
        "declare_subscriber",
        lent::declare_subscriber(1, 0, Some(key)),
        owned::build_declare_subscriber(1, 0, Some(key)).unwrap()
    );
    pair!(
        wrong,
        "declare_subscriber on an alias",
        lent::declare_subscriber(1, 7, None),
        owned::build_declare_subscriber(1, 7, None).unwrap()
    );
    pair!(
        wrong,
        "declare_queryable with info",
        lent::declare_queryable(2, 0, Some(key), info),
        {
            let mut built = owned::build_declare_queryable(2, 0, Some(key)).unwrap();
            owned::set_declare_queryable_info(&mut built, info);
            built
        }
    );
    pair!(
        wrong,
        "declare_token",
        lent::declare_token(3, 0, Some(key)),
        owned::build_declare_token(3, 0, Some(key)).unwrap()
    );
    pair!(
        wrong,
        "declare_token_nonlocal",
        lent::declare_token_nonlocal(3, 4, Some(key)),
        owned::build_declare_token_nonlocal(3, 4, Some(key)).unwrap()
    );
    pair!(
        wrong,
        "undeclare_kexpr",
        lent::undeclare_kexpr(5),
        owned::build_undeclare_kexpr(5)
    );
    pair!(
        wrong,
        "undeclare_subscriber",
        lent::undeclare_subscriber(1),
        owned::build_undeclare_subscriber(1)
    );
    pair!(
        wrong,
        "undeclare_queryable",
        lent::undeclare_queryable(2),
        owned::build_undeclare_queryable(2)
    );
    pair!(
        wrong,
        "undeclare_token",
        lent::undeclare_token(3),
        owned::build_undeclare_token(3)
    );
    // The retraction that names its key makes its body in an array of the caller's.
    pair!(
        wrong,
        "undeclare_subscriber_naming",
        {
            let named = lent::NamedKeyexpr::new(7, "tail").unwrap();
            // The value borrows `named`, so it is encoded inside this block.
            let mut slot = [0u8; SLOT];
            let len = {
                let mut sink = SliceSink::new(&mut slot);
                lent::undeclare_subscriber_naming(1, &named)
                    .encode(&mut sink)
                    .expect("fits the slot");
                sink.position()
            };
            NamedWritten { bytes: slot, len }
        },
        owned::build_undeclare_subscriber_on_wire(1, 7, "tail").unwrap()
    );
    pair!(
        wrong,
        "declare_final",
        lent::declare_final(),
        owned::build_declare_final()
    );
    pair!(
        wrong,
        "declare_token_reply",
        lent::declare_token_reply(9, key),
        owned::build_declare_token_reply(9, key).unwrap()
    );
    pair!(
        wrong,
        "declare_final_reply",
        lent::declare_final_reply(9),
        owned::build_declare_final_reply(9)
    );
    pair!(
        wrong,
        "interest subscribers",
        lent::interest(
            11,
            InterestKinds::SUBSCRIBERS,
            true,
            true,
            false,
            0,
            Some(key)
        ),
        owned_interest::build_interest_subscribers(11, true, true, 0, Some(key)).unwrap()
    );
    pair!(
        wrong,
        "interest propagated",
        lent::interest_propagated(lent::interest(
            11,
            InterestKinds::QUERYABLES,
            true,
            false,
            true,
            0,
            Some(key)
        )),
        owned_interest::build_interest_propagated(
            11,
            InterestKinds::QUERYABLES,
            true,
            false,
            Some((0, Some(key)))
        )
        .unwrap()
    );
    pair!(
        wrong,
        "interest final",
        lent::interest_final(11),
        owned_interest::build_interest_final(11)
    );
    pair!(
        wrong,
        "response_final",
        lent::response_final(13, QosLevel::DEFAULT),
        build_response_final(13, QosLevel::DEFAULT)
    );
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// What a window that has to keep its argument alive inside it hands back: the
/// encoded bytes and how many of them there are. It stands where the other
/// writers' views stand, and encodes through the same two calls.
struct NamedWritten {
    bytes: [u8; SLOT],
    len: usize,
}

impl NamedWritten {
    fn encode(&self, sink: &mut SliceSink<'_>) -> Result<(), sce_forge_runtime::codec::CodecError> {
        use sce_forge_runtime::codec::SceSink;
        sink.write_bytes(&self.bytes[..self.len])
    }
}

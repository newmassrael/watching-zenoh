// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The B-tree model of `heap_account::btree_bytes` against the allocator.
//!
//! The standard library does not say how many nodes a map holds, so the memory
//! report models them. A model is a belief until something that is not the model
//! reads the allocator: this fills real maps in the orders this workspace fills
//! them in (a key at a time in ascending order, and a sorted run appended onto a
//! map, which is how the overlay map folds its recent writes), counts the bytes
//! each holds, and requires the model to agree within 3%, at three sizes and for
//! three entry shapes, so a constant that fits one shape or one size is caught.
//!
//! The counter is per thread, so the test harness's allocations on other threads
//! cannot disturb it.

// The model lives in `heap_account`, which is `alloc`'s.
#![cfg(feature = "alloc")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;

use wz_session_core::heap_account::btree_bytes;

thread_local! {
    static OUTSTANDING: Cell<isize> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: every call is forwarded to the system allocator unchanged; the counter
// only observes the sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = OUTSTANDING.try_with(|c| c.set(c.get() + layout.size() as isize));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = OUTSTANDING.try_with(|c| c.set(c.get() - layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ =
            OUTSTANDING.try_with(|c| c.set(c.get() + new_size as isize - layout.size() as isize));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn outstanding() -> isize {
    OUTSTANDING.with(Cell::get)
}

const SIZES: [usize; 3] = [2_000, 20_000, 200_000];

/// An entry shaped like the census's row verdict: a key of three words and a
/// value of three words.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key3(usize, usize, usize);

/// Bytes a map built by `build` holds, and its length.
fn held<K: Ord, V>(build: impl FnOnce() -> BTreeMap<K, V>) -> (usize, usize) {
    let before = outstanding();
    let map = build();
    let bytes = (outstanding() - before) as usize;
    let len = map.len();
    drop(map);
    (bytes, len)
}

/// The model agrees with the allocator within 3%.
fn agree<K: Ord, V>(what: &str, build: impl FnOnce() -> BTreeMap<K, V>) {
    let (bytes, len) = held(build);
    let model = btree_bytes::<K, V>(len);
    let error = (model as f64 - bytes as f64).abs() / bytes as f64;
    assert!(
        error < 0.03,
        "{what} at {len} entries: the allocator holds {bytes} bytes, the model says {model} \
         ({:.1}% off)",
        error * 100.0
    );
}

#[test]
fn the_model_agrees_for_keys_inserted_in_ascending_order() {
    for n in SIZES {
        agree("u64 -> u64", || {
            let mut m = BTreeMap::new();
            for k in 0..n as u64 {
                m.insert(k, 0u64);
            }
            m
        });
        agree("u64 -> 88 bytes", || {
            let mut m = BTreeMap::new();
            for k in 0..n as u64 {
                m.insert(k, [0u8; 88]);
            }
            m
        });
        agree("three words -> three words", || {
            let mut m = BTreeMap::new();
            for k in 0..n {
                m.insert(Key3(0, 0, k), Key3(0, 0, 0));
            }
            m
        });
    }
}

/// The overlay map's way of growing: recent writes in a small map, folded into
/// the shared one by appending the sorted run.
#[test]
fn the_model_agrees_for_runs_appended_onto_a_map() {
    for n in SIZES {
        agree("runs of 100 appended", || {
            let mut base: BTreeMap<Key3, Key3> = BTreeMap::new();
            for chunk in 0..n / 100 {
                let mut delta = BTreeMap::new();
                for k in chunk * 100..chunk * 100 + 100 {
                    delta.insert(Key3(0, 0, k), Key3(0, 0, 0));
                }
                base.append(&mut delta);
            }
            base
        });
    }
}

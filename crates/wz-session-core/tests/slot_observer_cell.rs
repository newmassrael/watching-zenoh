// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The process-wide observer's cell: built in place, once, lent one holder at a time.
//!
//! The cell exists because the observer is large (about 16 KB on the Zephyr node's
//! target) and the node's stack is 32 KB. An install that takes the observer by value
//! holds it again in every call that hands it on, and the node's main frame was 69 KB of
//! them; the node's own loop ran below its stack and the first session it dialled wrote
//! over lwIP's memory. These tests hold the cell's contract. The property that mattered,
//! the stack a build needs, is a number of the target's code and not of a host's, which
//! is why the real image's frame sizes are read from its binary (the stack frame gate),
//! not from a test here.
//!
//! Needs the heap sinks (`alloc`, a default feature) to have something to register and
//! to drop, and compiles only on the fixed backing, where the observer module is.
#![cfg(all(feature = "bounded-heapless", feature = "alloc"))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_session_core::locality::Locality;
use wz_session_core::sink::{BoxedSink, SampleView};
use wz_session_core::slot_observer::{AlreadyInitialised, HeapSinks, ObserverCell, SlotObserverOf};

/// What a registered sink does when the observer drops it: counts.
struct CountOnDrop(Arc<AtomicUsize>);

impl Drop for CountOnDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn sink_that_counts_its_drop(drops: &Arc<AtomicUsize>) -> BoxedSink {
    let guard = CountOnDrop(Arc::clone(drops));
    BoxedSink::new(move |_sample: &dyn SampleView| {
        let _ = &guard;
    })
}

#[test]
fn the_observer_is_built_in_the_cell_and_stays_where_it_was_built() {
    let cell = ObserverCell::<HeapSinks>::new();
    assert!(!cell.is_initialised());
    let at = cell
        .init_with(|observer| observer as *mut SlotObserverOf<HeapSinks> as usize)
        .expect("an empty cell is built");
    assert!(cell.is_initialised());
    let again = {
        let mut guard = cell.borrow_mut();
        &mut *guard as *mut SlotObserverOf<HeapSinks> as usize
    };
    assert_eq!(
        at, again,
        "the observer the registration saw is the one every later borrow lends: it was not moved"
    );
}

#[test]
fn registrations_made_while_building_are_there_afterwards() {
    let cell = ObserverCell::<HeapSinks>::new();
    let drops = Arc::new(AtomicUsize::new(0));
    let id = cell
        .init_with(|observer| {
            observer
                .subscribers
                .register_sink("a/b", Locality::Any, sink_that_counts_its_drop(&drops))
                .expect("the subscriber registers")
        })
        .expect("built");
    let mut guard = cell.borrow_mut();
    assert_eq!(
        guard.subscribers.len(),
        1,
        "the registration is in the cell"
    );
    assert!(
        guard.subscribers.unregister(id),
        "the id the registration returned names the subscriber the cell holds"
    );
}

#[test]
fn a_second_build_is_refused_and_leaves_the_observer_as_it_was() {
    let cell = ObserverCell::<HeapSinks>::new();
    let drops = Arc::new(AtomicUsize::new(0));
    cell.init_with(|observer| {
        observer
            .subscribers
            .register_sink("a", Locality::Any, sink_that_counts_its_drop(&drops))
            .expect("registers")
    })
    .expect("built");
    let mut registered_again = false;
    let refused = cell.init_with(|_observer| registered_again = true);
    assert_eq!(refused, Err(AlreadyInitialised));
    assert!(
        !registered_again,
        "the refused build never ran its registration"
    );
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "nothing was dropped by the refusal"
    );
    assert_eq!(cell.borrow_mut().subscribers.len(), 1);
}

#[test]
fn one_holder_at_a_time() {
    let cell = ObserverCell::<HeapSinks>::new();
    assert!(
        cell.try_borrow_mut().is_none(),
        "a cell with no observer lends nothing"
    );
    cell.init_with(|_| ()).expect("built");
    {
        let _held = cell.try_borrow_mut().expect("an idle cell lends");
        assert!(
            cell.try_borrow_mut().is_none(),
            "a held cell lends nothing more"
        );
    }
    assert!(
        cell.try_borrow_mut().is_some(),
        "the guard's drop gives the observer back"
    );
}

#[test]
#[should_panic(expected = "borrowed before it was built")]
fn borrowing_before_the_build_panics() {
    let cell = ObserverCell::<HeapSinks>::new();
    let _ = cell.borrow_mut();
}

#[test]
#[should_panic(expected = "already borrowed")]
fn a_second_borrow_while_held_panics() {
    let cell = ObserverCell::<HeapSinks>::new();
    cell.init_with(|_| ()).expect("built");
    let _first = cell.borrow_mut();
    let _second = cell.borrow_mut();
}

#[test]
#[should_panic(expected = "already borrowed")]
fn a_borrow_from_inside_the_registration_panics() {
    let cell = ObserverCell::<HeapSinks>::new();
    let _ = cell.init_with(|_observer| {
        let _inner = cell.borrow_mut();
    });
}

#[test]
fn dropping_the_cell_drops_what_was_registered_once() {
    let drops = Arc::new(AtomicUsize::new(0));
    {
        let cell = ObserverCell::<HeapSinks>::new();
        cell.init_with(|observer| {
            for pattern in ["a", "b", "c"] {
                observer
                    .subscribers
                    .register_sink(pattern, Locality::Any, sink_that_counts_its_drop(&drops))
                    .expect("registers");
            }
        })
        .expect("built");
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    assert_eq!(
        drops.load(Ordering::SeqCst),
        3,
        "each registered sink dropped exactly once with the cell"
    );
}

#[test]
fn an_empty_cell_drops_nothing() {
    let cell = ObserverCell::<HeapSinks>::new();
    drop(cell);
}

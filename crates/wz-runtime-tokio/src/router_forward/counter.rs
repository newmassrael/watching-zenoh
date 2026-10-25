// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The router's witnesses: counts that rise as it works, readable from any thread.
//!
//! The router counted with `Cell<usize>`, which is right while one task drives every face and wrong
//! the moment two do: a `Cell` is not `Sync`, so the forwarder that holds one cannot be shared, and
//! `x.set(x.get() + 1)` from two threads loses an increment (read, read, write, write). The counters
//! are the first thing the data path writes that cannot live under a read lock, so each is its own
//! atomic (`docs/router-task-per-face.md`, phase 1).
//!
//! `Relaxed` throughout, and that is the whole of the memory-ordering argument: a counter publishes
//! nothing. No other data is made visible by reading it, no decision is taken on its value that
//! another memory location has to agree with, and it is read for reporting and for a test that
//! waits for it to reach a number. What it must keep is that no increment is lost, which every
//! atomic read-modify-write does at any ordering.

use std::sync::atomic::{AtomicUsize, Ordering};

/// A count that rises, shared between threads without a lock.
#[derive(Debug, Default)]
pub(super) struct Counter(AtomicUsize);

impl Counter {
    /// A counter at zero.
    pub(super) const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    /// The count now.
    pub(super) fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    /// One more.
    pub(super) fn bump(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// `n` more.
    pub(super) fn add(&self, n: usize) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// At least `n`: a peak, which is the one reading that is not a sum.
    #[cfg_attr(not(feature = "router-multicast-faces"), allow(dead_code))]
    pub(super) fn raise_to(&self, n: usize) {
        self.0.fetch_max(n, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::Counter;
    use std::sync::Arc;

    /// The three ways a counter rises, each from a known count.
    #[test]
    fn a_counter_rises_by_one_by_n_and_to_a_peak_and_never_falls() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);
        counter.bump();
        counter.bump();
        counter.add(5);
        assert_eq!(counter.get(), 7);
        counter.raise_to(3);
        assert_eq!(counter.get(), 7, "a peak below the count does not lower it");
        counter.raise_to(11);
        assert_eq!(counter.get(), 11);
    }

    /// What a `Cell` could not do: many threads counting at once lose none. Eight threads of a hundred
    /// thousand bumps each give exactly eight hundred thousand; the same loop over
    /// `x.set(x.get() + 1)` on a shared cell does not compile, and over a plain read and write of an
    /// atomic gives fewer on any machine with more than one core.
    #[test]
    fn counting_from_many_threads_loses_nothing() {
        const THREADS: usize = 8;
        const EACH: usize = 100_000;
        let counter = Arc::new(Counter::new());
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let counter = Arc::clone(&counter);
                std::thread::spawn(move || {
                    for _ in 0..EACH {
                        counter.bump();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("a counting thread ends");
        }
        assert_eq!(counter.get(), THREADS * EACH);
    }

    /// A peak taken from many threads is the greatest of what each offered.
    #[test]
    fn a_peak_raised_from_many_threads_is_the_greatest_offered() {
        let counter = Arc::new(Counter::new());
        let workers: Vec<_> = (1..=8usize)
            .map(|n| {
                let counter = Arc::clone(&counter);
                std::thread::spawn(move || {
                    for i in 0..1_000 {
                        counter.raise_to(n * 1_000 + i);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("a raising thread ends");
        }
        assert_eq!(counter.get(), 8 * 1_000 + 999);
    }
}

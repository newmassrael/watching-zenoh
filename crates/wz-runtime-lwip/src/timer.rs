// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Deadline-keyed timer queue — R311bc.
//!
//! Replaces R311av's `cx.waker().wake_by_ref()` busy-poll pattern with
//! a wake-on-deadline registration. A [`crate::time::SleepFuture`] or
//! [`crate::time::TimeoutFuture`] that has not yet elapsed registers
//! its waker with the queue along with the absolute deadline (in
//! microseconds, as reported by [`crate::time::ClockSource::now_us`]).
//! On every [`crate::LwipRuntime::run_until_idle`] pass the runtime
//! calls [`TimerQueue::pop_expired`] first; entries whose deadline has
//! elapsed have their waker invoked and are removed from the queue.
//! Pending entries stay in the heap until their deadline elapses.
//!
//! ## Why this matters (north star — composable framework MCU truth)
//!
//! The R311av self-wake pattern was correct but wasted power: every
//! `run_until_idle` pass re-polled the sleep future, the future re-
//! checked the clock, the future re-armed its own wake, ad infinitum.
//! On a battery-powered MCU the executor loop never went quiet so the
//! deploy could never `wfi()`-sleep between IRQs.
//!
//! With a real timer queue the executor pass is genuinely idle when
//! no task is ready and no timer has elapsed; the deploy main loop
//! can call `wfi()` and the next wake-up is driven by a SysTick or
//! HAL-timer ISR that crosses the next-deadline boundary. This is the
//! shape every MCU async runtime (embassy, RTIC, FreeRTOS) follows
//! for the same power-budget reason.
//!
//! ## Ordering
//!
//! `BinaryHeap<Reverse<TimerEntry>>` gives a min-heap by deadline.
//! Ties (multiple registrations at the same deadline) break by a
//! monotonic sequence number so the heap maintains a strict order
//! (required for `Ord`) and a deterministic wake order across
//! identical deadlines (FIFO by registration time).
//!
//! ## Drop semantics
//!
//! Dropping a [`crate::time::SleepFuture`] before its deadline does
//! NOT remove the entry from the heap. When the deadline eventually
//! elapses the registered waker fires harmlessly — the task is by
//! then past that sleep call, so the wake simply re-polls the task,
//! which finds no pending work and returns Pending again. The heap
//! size therefore tracks "long-lived dropped sleeps in flight",
//! bounded by `(poll-rate × max-deadline-distance)` for any deploy.
//! A per-entry cancellation flag (`Arc<AtomicBool>` checked during
//! `pop_expired`) is a deliberate R311bd+ refinement if a profile
//! ever reports growing heap retention as a real issue.
//!
//! ## Critical section discipline
//!
//! Both `register` and `pop_expired` take the inner
//! `critical_section::Mutex<RefCell<..>>` exactly once per call —
//! peek+pop is collapsed into a single CS window so the IRQ-disable
//! cost is amortised over each expired entry. Wakers are invoked
//! *outside* the CS so a user wake() impl that does its own work
//! (or even calls back into the runtime) does not deadlock.

use alloc::collections::BinaryHeap;
use core::cell::RefCell;
use core::cmp::Reverse;
use core::task::Waker;
use critical_section::Mutex;

struct TimerEntry {
    deadline_us: u64,
    seq: u64,
    waker: Waker,
}

// Ord/Eq derive: order by (deadline, seq). Waker is excluded from
// comparison because it does not implement Eq + Ord; seq monotonicity
// guarantees no two entries collide on the (deadline, seq) tuple, so
// the synthetic ordering is strict regardless of waker identity.
impl PartialEq for TimerEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline_us == other.deadline_us && self.seq == other.seq
    }
}

impl Eq for TimerEntry {}

impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.deadline_us, self.seq).cmp(&(other.deadline_us, other.seq))
    }
}

struct TimerQueueInner {
    heap: BinaryHeap<Reverse<TimerEntry>>,
    next_seq: u64,
}

/// Deadline-keyed wake registry. Held inside `Arc<RuntimeInner<C>>`
/// (see [`crate::runtime_impl`]) so [`crate::time::LwipTime`] and
/// the spawned-task layer share the same queue.
pub struct TimerQueue {
    inner: Mutex<RefCell<TimerQueueInner>>,
}

impl TimerQueue {
    /// Construct an empty queue. Allocation happens lazily on the
    /// first `register` call.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RefCell::new(TimerQueueInner {
                heap: BinaryHeap::new(),
                next_seq: 0,
            })),
        }
    }

    /// Register `waker` to be woken when wall-clock micros reach
    /// `deadline_us`. Multiple wakers may register on the same
    /// deadline; FIFO by registration sequence within a deadline.
    pub fn register(&self, deadline_us: u64, waker: Waker) {
        critical_section::with(|cs| {
            let mut q = self.inner.borrow(cs).borrow_mut();
            let seq = q.next_seq;
            q.next_seq = q.next_seq.wrapping_add(1);
            q.heap.push(Reverse(TimerEntry {
                deadline_us,
                seq,
                waker,
            }));
        });
    }

    /// Wake every entry whose `deadline_us <= now_us`. Wakers fire
    /// outside the critical section so a wake() that re-enters
    /// runtime APIs (e.g. setting a per-task atomic flag) does not
    /// deadlock against the CS-mutex.
    pub fn pop_expired(&self, now_us: u64) {
        loop {
            let entry = critical_section::with(|cs| {
                let mut q = self.inner.borrow(cs).borrow_mut();
                match q.heap.peek() {
                    Some(Reverse(top)) if top.deadline_us <= now_us => {
                        q.heap.pop().map(|Reverse(e)| e)
                    }
                    _ => None,
                }
            });
            match entry {
                Some(e) => e.waker.wake(),
                None => return,
            }
        }
    }

    /// Diagnostic: number of entries currently registered. Used by
    /// [`crate::LwipRuntime::block_on`] to distinguish "deadlocked
    /// future, no wake source" (panic) from "pending timer, clock
    /// will eventually advance" (legitimate wait state).
    pub fn pending_count(&self) -> usize {
        critical_section::with(|cs| self.inner.borrow(cs).borrow().heap.len())
    }

    /// Diagnostic: earliest deadline currently registered, or `None`
    /// if the queue is empty. A deploy main loop may inspect this to
    /// size its `wfi()`-sleep budget against a HAL timer; the
    /// runtime itself does not require the deploy to do so.
    pub fn next_deadline_us(&self) -> Option<u64> {
        critical_section::with(|cs| {
            self.inner
                .borrow(cs)
                .borrow()
                .heap
                .peek()
                .map(|Reverse(e)| e.deadline_us)
        })
    }
}

impl Default for TimerQueue {
    fn default() -> Self {
        Self::new()
    }
}

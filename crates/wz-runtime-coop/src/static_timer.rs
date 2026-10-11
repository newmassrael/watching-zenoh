// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The deadline-keyed timer queue on STATIC storage (`session-slot`, fixed-memory
//! step S6): the form of [`crate::timer`] the MCU session profile compiles in its
//! place, with the same surface and no heap.
//!
//! The heap form was a `BinaryHeap` that grew with every sleep a task registered
//! and shrank only when a deadline passed. This one is a table of `TIMERS`
//! entries the image declares ([`TimerTable`]), each a deadline and the waker to
//! raise at it. A sleep that finds the table full is NOT lost: [`TimerQueue::register`]
//! answers `false` and counts the refusal, and the future falls back to waking
//! itself for the next pass, which is the busy-poll the timer queue replaced and
//! is exactly as correct, only not idle. The next poll tries to register again,
//! so the sleep moves into the table as soon as an entry is free.
//!
//! Ties between entries at one deadline wake in registration order, as the heap
//! form's did (a sequence number breaks them).

use core::cell::{Cell, RefCell};
use core::task::Waker;

use critical_section::Mutex;

struct TimerEntry {
    deadline_us: u64,
    seq: u64,
    waker: Waker,
}

/// One entry of the table: empty, or a deadline waiting.
pub struct TimerSlot(Mutex<RefCell<Option<TimerEntry>>>);

impl TimerSlot {
    const fn new() -> Self {
        Self(Mutex::new(RefCell::new(None)))
    }
}

/// The timer table an image declares: `TIMERS` entries in a `static`, which the
/// runtime's cell ([`crate::runtime_impl::RuntimeCell`]) holds.
pub struct TimerTable<const TIMERS: usize> {
    slots: [TimerSlot; TIMERS],
}

impl<const TIMERS: usize> TimerTable<TIMERS> {
    /// A table of empty entries.
    pub const fn new() -> Self {
        Self {
            slots: [const { TimerSlot::new() }; TIMERS],
        }
    }

    pub(crate) fn queue(&'static self) -> TimerQueue {
        TimerQueue {
            slots: &self.slots,
            next_seq: Mutex::new(Cell::new(0)),
            refused: Mutex::new(Cell::new(0)),
        }
    }
}

impl<const TIMERS: usize> Default for TimerTable<TIMERS> {
    fn default() -> Self {
        Self::new()
    }
}

/// Deadline-keyed wake registry over a [`TimerTable`]. Held inside the runtime
/// so [`crate::time::CoopTime`] and the task pool share the same queue.
pub struct TimerQueue {
    slots: &'static [TimerSlot],
    next_seq: Mutex<Cell<u64>>,
    refused: Mutex<Cell<u32>>,
}

impl TimerQueue {
    /// Register `waker` to be woken when wall-clock micros reach `deadline_us`.
    /// `false` when every entry is taken: the refusal is counted
    /// ([`Self::refusals`]) and nothing is registered, so the caller wakes itself
    /// instead.
    pub fn register(&self, deadline_us: u64, waker: Waker) -> bool {
        critical_section::with(|cs| {
            let seq = {
                let next = self.next_seq.borrow(cs);
                let seq = next.get();
                next.set(seq.wrapping_add(1));
                seq
            };
            for slot in self.slots {
                let mut entry = slot.0.borrow(cs).borrow_mut();
                if entry.is_none() {
                    *entry = Some(TimerEntry {
                        deadline_us,
                        seq,
                        waker,
                    });
                    return true;
                }
            }
            let refused = self.refused.borrow(cs);
            refused.set(refused.get().saturating_add(1));
            false
        })
    }

    /// Wake every entry whose `deadline_us <= now_us`, earliest first. Wakers fire
    /// outside the critical section, as the heap form's do.
    pub fn pop_expired(&self, now_us: u64) {
        loop {
            let due = critical_section::with(|cs| {
                let mut best: Option<(usize, u64, u64)> = None;
                for (index, slot) in self.slots.iter().enumerate() {
                    if let Some(entry) = slot.0.borrow(cs).borrow().as_ref() {
                        if entry.deadline_us <= now_us
                            && best.map_or(true, |(_, deadline, seq)| {
                                (entry.deadline_us, entry.seq) < (deadline, seq)
                            })
                        {
                            best = Some((index, entry.deadline_us, entry.seq));
                        }
                    }
                }
                best.and_then(|(index, ..)| self.slots[index].0.borrow(cs).borrow_mut().take())
            });
            match due {
                Some(entry) => entry.waker.wake(),
                None => return,
            }
        }
    }

    /// Diagnostic: number of entries currently registered.
    pub fn pending_count(&self) -> usize {
        critical_section::with(|cs| {
            self.slots
                .iter()
                .filter(|slot| slot.0.borrow(cs).borrow().is_some())
                .count()
        })
    }

    /// Diagnostic: earliest deadline currently registered, or `None` if the table
    /// is empty.
    pub fn next_deadline_us(&self) -> Option<u64> {
        critical_section::with(|cs| {
            self.slots
                .iter()
                .filter_map(|slot| slot.0.borrow(cs).borrow().as_ref().map(|e| e.deadline_us))
                .min()
        })
    }

    /// How many sleeps were refused an entry (each woke itself for the next pass
    /// instead).
    pub fn refusals(&self) -> u32 {
        critical_section::with(|cs| self.refused.borrow(cs).get())
    }

    /// The entry count of the table.
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }
}

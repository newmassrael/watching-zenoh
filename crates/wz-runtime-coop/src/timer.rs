// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The deadline-keyed timer queue: one table of entries for every profile of this runtime.
//!
//! A [`crate::time::SleepFuture`] or [`crate::time::TimeoutFuture`] that has not yet elapsed
//! registers its waker with the queue along with its absolute deadline (in microseconds, as
//! [`crate::time::ClockSource::now_us`] reports it). On every [`crate::CoopRuntime::run_until_idle`]
//! pass the runtime calls [`TimerQueue::pop_expired`] first, which wakes every entry whose
//! deadline has passed and frees it. The executor pass is then genuinely idle when no task is
//! ready and no deadline has passed, so a deploy loop can sleep (`wfi()`) until the next one.
//!
//! ## Where the table lies
//!
//! - In a `static` the image declares (`TimerTable`, `session-slot`).
//! - Reserved once, when the runtime is made (`CoopRuntime::reserved`): `timers` entries.
//! - Grown by one entry whenever every entry is taken (`CoopRuntime::new`); an entry that comes
//!   free is reused, so the table is as long as the most deadlines that ever waited at once.
//!
//! A sleep that finds a fixed table full is NOT lost: [`TimerQueue::register`] answers `false`
//! and counts the refusal, and the future falls back to waking itself for the next pass, which
//! is exactly as correct, only not idle. The next poll tries to register again, so the sleep moves
//! into the table as soon as an entry is free.
//!
//! Ties between entries at one deadline wake in registration order (a sequence number breaks
//! them). Wakers fire outside the critical section, so a wake that re-enters the runtime does not
//! deadlock. A sleep dropped before its deadline leaves its entry, which wakes its task once for
//! nothing when the deadline passes and is freed then.

use core::cell::{Cell, RefCell};
use core::task::Waker;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::boxed::Box;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;
use critical_section::{CriticalSection, Mutex};

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

    /// An entry that holds `entry` from the start: the one a grown table adds.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn holding(entry: TimerEntry) -> Self {
        Self(Mutex::new(RefCell::new(Some(entry))))
    }
}

/// The timer table an image declares: `TIMERS` entries in a `static`, which the
/// runtime's cell (`RuntimeCell`) holds.
#[cfg(feature = "session-slot")]
pub struct TimerTable<const TIMERS: usize> {
    slots: [TimerSlot; TIMERS],
}

#[cfg(feature = "session-slot")]
impl<const TIMERS: usize> TimerTable<TIMERS> {
    /// A table of empty entries.
    pub const fn new() -> Self {
        Self {
            slots: [const { TimerSlot::new() }; TIMERS],
        }
    }

    pub(crate) fn queue(&'static self) -> TimerQueue {
        TimerQueue::over(Slots::Table(&self.slots))
    }
}

#[cfg(feature = "session-slot")]
impl<const TIMERS: usize> Default for TimerTable<TIMERS> {
    fn default() -> Self {
        Self::new()
    }
}

/// Where a queue's entries are.
enum Slots {
    /// A `static` table the image declares.
    #[cfg(feature = "session-slot")]
    Table(&'static [TimerSlot]),
    /// A table reserved when the runtime was made.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    Reserved(Box<[TimerSlot]>),
    /// A table that grows by an entry when every entry is taken.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    Growing(Mutex<RefCell<Vec<TimerSlot>>>),
}

/// Deadline-keyed wake registry over a table of entries. Held inside the runtime
/// so [`crate::time::CoopTime`] and the task pool share the same queue.
pub struct TimerQueue {
    slots: Slots,
    next_seq: Mutex<Cell<u64>>,
    refused: Mutex<Cell<u32>>,
}

impl TimerQueue {
    fn over(slots: Slots) -> Self {
        Self {
            slots,
            next_seq: Mutex::new(Cell::new(0)),
            refused: Mutex::new(Cell::new(0)),
        }
    }

    /// A table that grows by an entry when every entry is taken.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn growing() -> Self {
        Self::over(Slots::Growing(Mutex::new(RefCell::new(Vec::new()))))
    }

    /// `timers` entries, reserved now: a deadline past them is refused, counted, and none
    /// allocates.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn reserved(timers: usize) -> Self {
        Self::over(Slots::Reserved(
            (0..timers).map(|_| TimerSlot::new()).collect(),
        ))
    }

    /// Run `f` over the table's entries, inside the critical section `cs`.
    // A `static` table's entries need no section to be reached; a grown one's list does.
    #[cfg_attr(feature = "session-slot", allow(unused_variables))]
    fn with_slots<R>(&self, cs: CriticalSection<'_>, f: impl FnOnce(&[TimerSlot]) -> R) -> R {
        match &self.slots {
            #[cfg(feature = "session-slot")]
            Slots::Table(slots) => f(slots),
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            Slots::Reserved(slots) => f(slots),
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            Slots::Growing(grown) => f(&grown.borrow(cs).borrow()),
        }
    }

    /// Register `waker` to be woken when wall-clock micros reach `deadline_us`.
    /// `false` when a fixed table has every entry taken: the refusal is counted
    /// ([`Self::refusals`]) and nothing is registered, so the caller wakes itself
    /// instead. A grown table adds an entry and answers `true`.
    pub fn register(&self, deadline_us: u64, waker: Waker) -> bool {
        crate::cs::with(|cs| {
            let seq = {
                let next = self.next_seq.borrow(cs);
                let seq = next.get();
                next.set(seq.wrapping_add(1));
                seq
            };
            let mut entry = Some(TimerEntry {
                deadline_us,
                seq,
                waker,
            });
            self.with_slots(cs, |slots| {
                for slot in slots {
                    let mut held = slot.0.borrow(cs).borrow_mut();
                    if held.is_none() {
                        *held = entry.take();
                        return;
                    }
                }
            });
            let Some(entry) = entry else {
                return true;
            };
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            if let Slots::Growing(grown) = &self.slots {
                grown
                    .borrow(cs)
                    .borrow_mut()
                    .push(TimerSlot::holding(entry));
                return true;
            }
            // The entry was not placed: its waker goes with it.
            drop(entry);
            let refused = self.refused.borrow(cs);
            refused.set(refused.get().saturating_add(1));
            false
        })
    }

    /// Wake every entry whose `deadline_us <= now_us`, earliest first. Wakers fire
    /// outside the critical section.
    pub fn pop_expired(&self, now_us: u64) {
        loop {
            let due = crate::cs::with(|cs| {
                self.with_slots(cs, |slots| {
                    earliest(cs, slots, now_us)
                        .and_then(|(index, _)| slots[index].0.borrow(cs).borrow_mut().take())
                })
            });
            match due {
                Some(entry) => entry.waker.wake(),
                None => return,
            }
        }
    }

    /// Diagnostic: number of entries currently registered.
    pub fn pending_count(&self) -> usize {
        crate::cs::with(|cs| {
            self.with_slots(cs, |slots| {
                slots
                    .iter()
                    .filter(|slot| slot.0.borrow(cs).borrow().is_some())
                    .count()
            })
        })
    }

    /// Diagnostic: earliest deadline currently registered, or `None` if the table
    /// is empty.
    pub fn next_deadline_us(&self) -> Option<u64> {
        crate::cs::with(|cs| {
            self.with_slots(cs, |slots| {
                earliest(cs, slots, u64::MAX).map(|(_, deadline_us)| deadline_us)
            })
        })
    }

    /// How many sleeps were refused an entry (each woke itself for the next pass
    /// instead). A grown table refuses none.
    pub fn refusals(&self) -> u32 {
        crate::cs::with(|cs| self.refused.borrow(cs).get())
    }

    /// The entry count of the table: for a grown one, the entries it has grown to so far.
    pub fn capacity(&self) -> usize {
        crate::cs::with(|cs| self.with_slots(cs, |slots| slots.len()))
    }
}

/// The entry of `slots` due first at `until_us` or before, ties in registration order: its index
/// and its deadline. One body for the pass that wakes what is due and for the look at what is next.
#[inline(never)]
fn earliest(cs: CriticalSection<'_>, slots: &[TimerSlot], until_us: u64) -> Option<(usize, u64)> {
    let mut best: Option<(usize, u64, u64)> = None;
    for (index, slot) in slots.iter().enumerate() {
        if let Some(entry) = slot.0.borrow(cs).borrow().as_ref() {
            if entry.deadline_us <= until_us
                && best.map_or(true, |(_, deadline, seq)| {
                    (entry.deadline_us, entry.seq) < (deadline, seq)
                })
            {
                best = Some((index, entry.deadline_us, entry.seq));
            }
        }
    }
    best.map(|(index, deadline_us, _)| (index, deadline_us))
}

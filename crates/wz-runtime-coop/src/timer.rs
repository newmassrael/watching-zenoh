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
//!
//! ## A runtime nothing sleeps on
//!
//! A pass and a look at the next deadline walk the entries only once a deadline has been placed
//! in one (`TableWalk`): until then the table is empty and they answer at once. The walk is
//! reached only through the entry `register` places, so a build in which no task sleeps (an
//! engine whose sessions keep their few deadlines, the lease, the keep-alive, the next dial and
//! the idle wait, in fixed places of their own and read them off the clock at each step) links
//! no walk of a table at all.

use core::cell::{Cell, RefCell};
use core::task::Waker;

use crate::atomic::{AtomicPtr, Ordering};

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::boxed::Box;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use core::alloc::Layout;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use core::ops::{Deref, DerefMut};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use core::ptr::{self, NonNull};
use critical_section::{CriticalSection, Mutex};

/// The due wakers [`TimerQueue::pop_expired`] takes out in one section: a few, because they are
/// on the stack of the pass, and enough that a pass rarely needs a second section.
const WAKE_BATCH: usize = 4;

struct TimerEntry {
    deadline_us: u64,
    seq: u64,
    waker: Waker,
}

/// One entry of the table: empty, or a deadline waiting. The table is borrowed whole, once, inside
/// a critical section, so an entry carries no lock of its own.
pub struct TimerSlot(Option<TimerEntry>);

impl TimerSlot {
    const fn new() -> Self {
        Self(None)
    }
}

/// A table's entries behind the runtime's critical section, of a length the table's type states:
/// what `critical_section::Mutex` is for a value whose size is known.
#[cfg(feature = "session-slot")]
struct Entries<T: ?Sized>(RefCell<T>);

// SAFETY: the entries are borrowed only through `Entries::borrow`, which asks for a critical
// section, so one context at a time reaches them; what they hold (deadlines and wakers) may be
// handed between contexts.
#[cfg(feature = "session-slot")]
unsafe impl<T: ?Sized + Send> Sync for Entries<T> {}

#[cfg(feature = "session-slot")]
impl<T: ?Sized> Entries<T> {
    fn borrow<'cs>(&'cs self, _cs: CriticalSection<'cs>) -> &'cs RefCell<T> {
        &self.0
    }
}

/// The timer table an image declares: `TIMERS` entries in a `static`, which the
/// runtime's cell (`RuntimeCell`) holds.
#[cfg(feature = "session-slot")]
pub struct TimerTable<const TIMERS: usize> {
    entries: Entries<[TimerSlot; TIMERS]>,
}

#[cfg(feature = "session-slot")]
impl<const TIMERS: usize> TimerTable<TIMERS> {
    /// A table of empty entries.
    pub const fn new() -> Self {
        Self {
            entries: Entries(RefCell::new([const { TimerSlot::new() }; TIMERS])),
        }
    }

    pub(crate) fn queue(&'static self) -> TimerQueue {
        TimerQueue::over(Slots::Table(&self.entries))
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
    Table(&'static Entries<[TimerSlot]>),
    /// The runtime's own table: reserved when the runtime was made, or grown by an entry when
    /// every entry is taken (`TimerQueue::grow`). One form for both, so every look at the entries
    /// is one body and not one for each.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    Owned(Mutex<RefCell<Vec<TimerSlot>>>),
    /// Entries in memory the table does not own, placed with the runtime's state
    /// (`TimerQueue::placed`): a table that never grows.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    Lent(Mutex<RefCell<LentSlots>>),
}

/// Entries written in memory the table does not own, dropped where they lie with the table.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
struct LentSlots {
    first: NonNull<TimerSlot>,
    len: usize,
}

// SAFETY: the entries are the table's alone, reached only through its critical section, and what
// they hold (deadlines and wakers) may be handed between contexts.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
unsafe impl Send for LentSlots {}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl Deref for LentSlots {
    type Target = [TimerSlot];

    fn deref(&self) -> &[TimerSlot] {
        // SAFETY: `len` entries were written at `first` and stand until this is dropped.
        unsafe { core::slice::from_raw_parts(self.first.as_ptr(), self.len) }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl DerefMut for LentSlots {
    fn deref_mut(&mut self) -> &mut [TimerSlot] {
        // SAFETY: as `deref`, and `&mut self` is the one way to them.
        unsafe { core::slice::from_raw_parts_mut(self.first.as_ptr(), self.len) }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl Drop for LentSlots {
    fn drop(&mut self) {
        // SAFETY: the entries are live and dropped once, here; their memory is not this table's.
        unsafe { ptr::drop_in_place(ptr::slice_from_raw_parts_mut(self.first.as_ptr(), self.len)) }
    }
}

/// Deadline-keyed wake registry over a table of entries. Held inside the runtime
/// so [`crate::time::CoopTime`] and the task pool share the same queue.
pub struct TimerQueue {
    slots: Slots,
    next_seq: Mutex<Cell<u64>>,
    refused: Mutex<Cell<u32>>,
    /// The walk of the entries, once a deadline has been placed in one: null until then, and
    /// `TABLE_WALK` from then on. Only `register` names the walk, so a build that registers
    /// no deadline links none of it.
    walk: AtomicPtr<TableWalk>,
    /// Places a deadline no entry holds in an entry of its own: a table that grows has it
    /// (`grow_by_one`), and only that table names it, so a runtime whose table is reserved links
    /// none of the growth.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    grow: Option<GrowFn>,
}

/// Place a deadline in a new entry of the table, or hand it back when the heap has no room for
/// the entry.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
type GrowFn = fn(&mut Vec<TimerSlot>, TimerEntry) -> Result<(), TimerEntry>;

/// What a pass and a look ahead do over the entries of a table a deadline has been placed in.
struct TableWalk {
    /// Wake every entry due at the time given ([`TimerQueue::pop_expired`]).
    pass: fn(&TimerQueue, u64),
    /// The earliest deadline held ([`TimerQueue::next_deadline_us`]).
    next: fn(&TimerQueue) -> Option<u64>,
}

/// The one walk of a table, which every queue points at once it holds a deadline.
static TABLE_WALK: TableWalk = TableWalk {
    pass: TimerQueue::wake_due,
    next: TimerQueue::earliest_deadline,
};

impl TimerQueue {
    fn over(slots: Slots) -> Self {
        Self {
            slots,
            next_seq: Mutex::new(Cell::new(0)),
            refused: Mutex::new(Cell::new(0)),
            walk: AtomicPtr::new(core::ptr::null_mut()),
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            grow: None,
        }
    }

    /// A table that grows by an entry when every entry is taken.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn growing() -> Self {
        let mut queue = Self::over(Slots::Owned(Mutex::new(RefCell::new(Vec::new()))));
        queue.grow = Some(grow_by_one);
        queue
    }

    /// `timers` entries, reserved now: a deadline past them is refused, counted, and none
    /// allocates.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn reserved(timers: usize) -> Self {
        Self::over(Slots::Owned(Mutex::new(RefCell::new(
            empty_slots(timers).into_vec(),
        ))))
    }

    /// `count` empty entries written at `first`, in memory the table does not own: a deadline
    /// past them is refused, counted, and none allocates. The entries are dropped where they lie
    /// with the table.
    ///
    /// # Safety
    /// `first` is aligned and valid for writes of `count` entries, and nothing else uses them
    /// while the table stands.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) unsafe fn placed(first: NonNull<TimerSlot>, count: usize) -> Self {
        for at in 0..count {
            // SAFETY: the caller's: `at` is below `count`, written once here.
            unsafe { first.as_ptr().add(at).write(TimerSlot::new()) };
        }
        Self::over(Slots::Lent(Mutex::new(RefCell::new(LentSlots {
            first,
            len: count,
        }))))
    }

    /// The table of a runtime made for `timers` deadlines at once: a table of no entries for 0,
    /// made with no reservation at all, and [`Self::reserved`] otherwise. Always inlined, so a
    /// runtime whose maker states its count as a constant links only the making of that count: a
    /// build in which no task sleeps reserves no entry and links no reservation of entries.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[inline(always)]
    pub(crate) fn of_rows(timers: usize) -> Self {
        if timers == 0 {
            Self::over(Slots::Owned(Mutex::new(RefCell::new(Vec::new()))))
        } else {
            Self::reserved(timers)
        }
    }

    /// Run `f` over the table's entries, borrowed once inside the critical section `cs`. `f`
    /// runs no code but this module's: a waker it takes out is woken or dropped after. A table
    /// already borrowed is handed over as one of no entries, which places, holds and wakes nothing.
    fn with_slots<R>(&self, cs: CriticalSection<'_>, f: impl FnOnce(&mut [TimerSlot]) -> R) -> R {
        match &self.slots {
            #[cfg(feature = "session-slot")]
            Slots::Table(entries) => match entries.borrow(cs).try_borrow_mut() {
                Ok(mut slots) => f(&mut slots),
                Err(_) => f(&mut []),
            },
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            Slots::Owned(owned) => match owned.borrow(cs).try_borrow_mut() {
                Ok(mut slots) => f(&mut slots),
                Err(_) => f(&mut []),
            },
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            Slots::Lent(lent) => match lent.borrow(cs).try_borrow_mut() {
                Ok(mut slots) => f(&mut slots),
                Err(_) => f(&mut []),
            },
        }
    }

    /// Register `waker` to be woken when wall-clock micros reach `deadline_us`.
    /// `false` when a fixed table has every entry taken: the refusal is counted
    /// ([`Self::refusals`]) and nothing is registered, so the caller wakes itself
    /// instead. A grown table adds an entry and answers `true`, or refuses as a fixed one
    /// does when the heap has no room for the entry.
    pub fn register(&self, deadline_us: u64, waker: Waker) -> bool {
        crate::cs::with(|cs| {
            let seq = {
                let next = self.next_seq.borrow(cs);
                let seq = next.get();
                next.set(seq.wrapping_add(1));
                seq
            };
            let entry = TimerEntry {
                deadline_us,
                seq,
                waker,
            };
            let unplaced = self.with_slots(cs, |slots| {
                match slots.iter_mut().find(|slot| slot.0.is_none()) {
                    Some(slot) => {
                        slot.0 = Some(entry);
                        None
                    }
                    None => Some(entry),
                }
            });
            let Some(entry) = unplaced else {
                self.hold_walk();
                return true;
            };
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            let entry = match (self.grow, &self.slots) {
                (Some(grow), Slots::Owned(owned)) => match owned.borrow(cs).try_borrow_mut() {
                    Ok(mut slots) => match grow(&mut slots, entry) {
                        Ok(()) => {
                            self.hold_walk();
                            return true;
                        }
                        Err(entry) => entry,
                    },
                    Err(_) => entry,
                },
                _ => entry,
            };
            // The entry was not placed: its waker goes with it.
            drop(entry);
            let refused = self.refused.borrow(cs);
            refused.set(refused.get().saturating_add(1));
            false
        })
    }

    /// A deadline is placed: from now on a pass and a look ahead walk the entries.
    fn hold_walk(&self) {
        self.walk.store(
            core::ptr::from_ref(&TABLE_WALK).cast_mut(),
            Ordering::Release,
        );
    }

    /// The walk of the entries, once a deadline has been placed in one.
    fn walk(&self) -> Option<&'static TableWalk> {
        // SAFETY: the pointer is null or `TABLE_WALK`'s (`hold_walk`), a `static`.
        unsafe { self.walk.load(Ordering::Acquire).as_ref() }
    }

    /// Wake every entry whose `deadline_us <= now_us`, earliest first. Wakers fire
    /// outside the critical section. Nothing for a queue no deadline was ever placed in.
    pub fn pop_expired(&self, now_us: u64) {
        if let Some(walk) = self.walk() {
            (walk.pass)(self, now_us);
        }
    }

    /// [`Self::pop_expired`] over a table a deadline was placed in.
    ///
    /// The due entries are taken out `WAKE_BATCH` at a time, earliest first, in one section
    /// each, so a pass that finds none or a few due takes one section. An entry a waker registers
    /// while this wakes, already due, is woken no later than the next pass. Out of line: the batch is on this
    /// call's frame, which is gone before the executor polls the tasks it woke.
    #[inline(never)]
    fn wake_due(&self, now_us: u64) {
        loop {
            let mut due: [Option<Waker>; WAKE_BATCH] = [const { None }; WAKE_BATCH];
            let taken = crate::cs::with(|cs| {
                self.with_slots(cs, |slots| {
                    let mut taken: usize = 0;
                    for place in due.iter_mut() {
                        let Some(waker) = take_earliest(slots, now_us) else {
                            break;
                        };
                        *place = Some(waker);
                        taken = taken.saturating_add(1);
                    }
                    taken
                })
            });
            for waker in due.into_iter().flatten() {
                waker.wake();
            }
            if taken < WAKE_BATCH {
                return;
            }
        }
    }

    /// Diagnostic: number of entries currently registered.
    pub fn pending_count(&self) -> usize {
        crate::cs::with(|cs| {
            self.with_slots(cs, |slots| {
                slots.iter().filter(|slot| slot.0.is_some()).count()
            })
        })
    }

    /// Diagnostic: earliest deadline currently registered, or `None` if the table
    /// is empty.
    pub fn next_deadline_us(&self) -> Option<u64> {
        self.walk().and_then(|walk| (walk.next)(self))
    }

    /// [`Self::next_deadline_us`] over a table a deadline was placed in.
    fn earliest_deadline(&self) -> Option<u64> {
        crate::cs::with(|cs| {
            self.with_slots(cs, |slots| {
                earliest(slots, u64::MAX).map(|(_, deadline_us)| deadline_us)
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

/// Place `entry` in a new entry of a table that grows, or hand it back when the heap has no room
/// for the entry.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
fn grow_by_one(slots: &mut Vec<TimerSlot>, entry: TimerEntry) -> Result<(), TimerEntry> {
    if slots.try_reserve(1).is_err() {
        return Err(entry);
    }
    slots.push(TimerSlot(Some(entry)));
    Ok(())
}

/// `count` empty entries in one allocation of their size; none for a count past the address
/// space or one the heap has no room for, whose table then refuses every sleep an entry, counted.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
fn empty_slots(count: usize) -> Box<[TimerSlot]> {
    let layout = match Layout::array::<TimerSlot>(count) {
        Ok(layout) if layout.size() > 0 => layout,
        _ => return Box::default(),
    };
    // SAFETY: the layout's size is not zero.
    let block = unsafe { alloc::alloc::alloc(layout) };
    if block.is_null() {
        return Box::default();
    }
    let first = block.cast::<TimerSlot>();
    for at in 0..count {
        // SAFETY: `at` is below `count`, so the place is one of the allocation's entries, aligned
        // for one, written once here.
        unsafe { first.add(at).write(TimerSlot::new()) };
    }
    // SAFETY: the global allocator made the allocation with the layout a boxed slice of `count`
    // entries has (`Layout::array`), and every entry is written above.
    unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(first, count)) }
}

/// Take the waker of the entry of `slots` due first at `until_us` or before out of the table,
/// its entry free from then; `None` when none is due.
// Out of line: the batch's loop has a count of its own, and the compiler copies whatever its body
// holds once for each place of the batch; a call is what it copies.
#[inline(never)]
fn take_earliest(slots: &mut [TimerSlot], until_us: u64) -> Option<Waker> {
    let (index, _) = earliest(slots, until_us)?;
    slots.get_mut(index)?.0.take().map(|entry| entry.waker)
}

/// The entry of `slots` due first at `until_us` or before, ties in registration order: its index
/// and its deadline. One body for the pass that wakes what is due and for the look at what is next.
#[inline(never)]
fn earliest(slots: &[TimerSlot], until_us: u64) -> Option<(usize, u64)> {
    let mut best: Option<(usize, u64, u64)> = None;
    for (index, slot) in slots.iter().enumerate() {
        if let Some(entry) = &slot.0 {
            if entry.deadline_us <= until_us
                && best.is_none_or(|(_, deadline, seq)| {
                    (entry.deadline_us, entry.seq) < (deadline, seq)
                })
            {
                best = Some((index, entry.deadline_us, entry.seq));
            }
        }
    }
    best.map(|(index, deadline_us, _)| (index, deadline_us))
}

#[cfg(all(test, feature = "alloc", not(feature = "session-slot")))]
mod tests {
    use super::*;
    use core::task::{RawWaker, RawWakerVTable};

    /// A waker that does nothing.
    fn noop_waker() -> Waker {
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(core::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        // SAFETY: every function of the vtable ignores its data pointer.
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }

    /// A reserved table has the entries it was told, all empty; a count past the address space
    /// makes none, and a sleep then finds no entry and is refused, counted.
    #[test]
    fn a_reserved_table_has_its_entries_and_one_past_the_address_space_has_none() {
        let slots = empty_slots(3);
        assert_eq!(slots.len(), 3);
        assert!(slots.iter().all(|slot| slot.0.is_none()));
        assert_eq!(empty_slots(0).len(), 0);
        assert_eq!(empty_slots(usize::MAX).len(), 0);
        let queue = TimerQueue::reserved(usize::MAX);
        assert_eq!(queue.capacity(), 0);
        assert!(!queue.register(5, noop_waker()));
        assert_eq!(queue.refusals(), 1);
    }

    /// A table the heap has no room for is made with no entries, and a sleep then finds none and
    /// is refused, counted; a table that grows refuses a deadline the heap has no room to add an
    /// entry for, counted, and places the next once it has. Turned red by `empty_slots` or
    /// `grow_by_one` asking the heap for memory it cannot fail to get (`handle_alloc_error`,
    /// `push` without a reservation), which ends the process.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_table_the_heap_has_no_room_for_refuses_its_sleeps() {
        assert_eq!(crate::table_tests::refused(|| empty_slots(3)).len(), 0);
        let queue = crate::table_tests::refused(|| TimerQueue::reserved(3));
        assert_eq!(queue.capacity(), 0);
        assert!(!queue.register(5, noop_waker()));
        assert_eq!(queue.refusals(), 1);

        let growing = TimerQueue::growing();
        assert!(!crate::table_tests::refused(
            || growing.register(1, noop_waker())
        ));
        assert_eq!((growing.capacity(), growing.refusals()), (0, 1));
        assert!(growing.register(2, noop_waker()), "the heap has room again");
        assert_eq!((growing.capacity(), growing.pending_count()), (1, 1));
    }

    /// The table asked for from inside its own borrow is handed over as one of no entries.
    /// Turned red by a `with_slots` that borrows with `borrow_mut`, which panics there.
    #[test]
    fn a_table_asked_for_inside_its_own_borrow_has_no_entries() {
        let queue = TimerQueue::reserved(2);
        let inner = crate::cs::with(|cs| {
            queue.with_slots(cs, |outer| {
                assert_eq!(outer.len(), 2);
                queue.with_slots(cs, |inner| inner.len())
            })
        });
        assert_eq!(inner, 0);
    }

    /// Only a table that grows places a deadline no entry holds; a reserved one refuses it,
    /// counted, and keeps the entries it was made with.
    #[test]
    fn only_a_growing_table_places_a_deadline_no_entry_holds() {
        let reserved = TimerQueue::reserved(1);
        assert!(reserved.register(1, noop_waker()));
        assert!(
            !reserved.register(2, noop_waker()),
            "the one entry is taken"
        );
        assert_eq!((reserved.capacity(), reserved.refusals()), (1, 1));
        let growing = TimerQueue::growing();
        assert!(growing.register(1, noop_waker()));
        assert!(growing.register(2, noop_waker()));
        assert_eq!((growing.capacity(), growing.refusals()), (2, 0));
        assert_eq!(growing.pending_count(), 2);
    }

    /// A table made for no deadline has no entry and refuses a sleep one, counted, which then ends
    /// by polling; one made for some has as many.
    ///
    /// # Control
    ///
    /// A making that reserved entries for a count of 0 reds the capacity of the first.
    #[test]
    fn a_table_made_for_no_deadline_has_no_entry_and_refuses_a_sleep_one() {
        let none = TimerQueue::of_rows(0);
        assert_eq!(none.capacity(), 0);
        assert!(!none.register(5, noop_waker()));
        assert_eq!(none.refusals(), 1);
        assert_eq!(none.next_deadline_us(), None);
        let some = TimerQueue::of_rows(3);
        assert_eq!(some.capacity(), 3);
        assert!(some.register(5, noop_waker()));
        assert_eq!(some.next_deadline_us(), Some(5));
    }

    /// A queue no deadline was placed in walks no table: a pass and a look ahead answer at once,
    /// with nothing. The first deadline placed, in a reserved entry or a grown one, is seen by
    /// both; one refused for want of an entry leaves the queue as it was.
    ///
    /// # Control
    ///
    /// A `register` that placed its deadline without holding the walk reds the look ahead after
    /// the first placement; one that held it for a refused deadline reds the first assertions.
    #[test]
    fn a_queue_walks_its_entries_only_once_a_deadline_is_placed() {
        let none = TimerQueue::reserved(0);
        assert!(!none.register(5, noop_waker()));
        assert!(none.walk().is_none(), "a refused deadline holds no walk");
        assert_eq!(none.next_deadline_us(), None);
        let queue = TimerQueue::reserved(2);
        assert!(queue.walk().is_none());
        assert_eq!(queue.next_deadline_us(), None);
        queue.pop_expired(u64::MAX);
        assert!(queue.register(30, noop_waker()));
        assert_eq!(queue.next_deadline_us(), Some(30));
        queue.pop_expired(10);
        assert_eq!(queue.pending_count(), 1, "not yet due");
        queue.pop_expired(30);
        assert_eq!(queue.pending_count(), 0);
        assert_eq!(
            queue.next_deadline_us(),
            None,
            "the walk stays, over an empty table"
        );
        let growing = TimerQueue::growing();
        assert!(growing.register(7, noop_waker()));
        assert_eq!(
            growing.next_deadline_us(),
            Some(7),
            "a grown entry holds the walk too"
        );
    }
}

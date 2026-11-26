// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A time base the program supplies (`time-base`): the clock the timers of a session run on when
//! the program, and not the system, says what time it is.
//!
//! A session times its lease, its keep-alive, its handshake and its other deadlines by a monotonic
//! clock, which is the system's unless the program hands it one of these. A program that runs the
//! session inside a simulation (paused, or faster or slower than the wall clock) reads its own
//! time through a [`ProgramTime`], and a deadline then passes when that time passes it, however
//! long the wall clock has run. A session given none reads the system's clock, as it always has.
//!
//! ## Reading
//!
//! The program's reading is held monotonic: a reading below one already given is the one already
//! given. Every deadline is a comparison with a reading, and a clock that went back would put a
//! deadline armed later before one armed earlier.
//!
//! ## Waiting
//!
//! A wait for a time ([`ProgramSleep`]) cannot be handed to the system, whose timers run on the
//! wall clock. A wait registers with the time base instead, and the program tells the time base
//! when its time has moved on ([`TimeBaseHold::advanced`]): each wait whose time has come is woken
//! then. A program that moves its time and says nothing wakes none. An engine that the program
//! steps reads the time at each step and needs no telling; one that waits on threads of its own
//! waits until it is told, on a waker it watches the time base with ([`TimeBaseHold::watch`]),
//! which each word wakes, so the engine's one wait (over its links) is ended by the word too.
//!
//! A word wakes in place. The waits lie in a table kept in order of deadline, the latest first, so
//! the ones whose time has come are taken from its end, earliest first; the wakers then run with no
//! lock of the time base held, at most `WAKE_BATCH` at a time from a batch on the stack of the
//! caller, so a word takes no memory however many it wakes.
//!
//! ## Room
//!
//! The waits and the watches lie in two tables of the time base. A session that takes no memory
//! once it is open sets aside, when it opens, the slots it will use ([`TimeBaseHold::reserve`]):
//! the tables grow then, and a wait or a watch made from the room it is given ([`TimeBaseRoom`])
//! lies in one of those slots and never grows them. One past the room's slots is refused and
//! counted ([`TimeBaseHold::refused`]): a refused wait ends at once, as one whose time has come
//! does, and a refused watch is not made. A wait or a watch made with no room
//! ([`TimeBaseRef::sleep_until`], [`TimeBaseHold::watch`]) grows a full table, for an engine whose
//! timers start while it runs and have no count at its open.
//!
//! ## Holding
//!
//! A time base is held ([`TimeBaseHold`]) by the program, by each configuration that names it and
//! by each session opened on it, and the program's read goes when the last of them does. An engine
//! whose clock is a copyable value reads it through a [`TimeBaseRef`], beside a hold kept for as
//! long as its session is. The time base itself is never freed: when its last hold goes it returns
//! to a pool a later one is taken from, so a reference never dangles, and a reference that
//! outlives the holds it was taken under reads the time base as past every deadline. Whatever
//! still waits on it then ends, and nothing reads another program's time through it. Each time
//! base has its place in the pool from when it is made, so the last hold's going takes no memory,
//! whichever hold that is.

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use alloc::boxed::Box;
use alloc::vec::Vec;

use wz_host_sync::{Mutex, MutexGuard, RwLock};

/// What the program's time is read through.
pub trait ProgramTime: Send + Sync {
    /// The program's time, in nanoseconds since an epoch of its choosing. Called from whichever
    /// thread reads a session's clock, possibly several at once; it must not let go of the time
    /// base it reads for.
    fn now_ns(&self) -> u64;
}

/// The program's read while a hold has it, and the lease it was installed under: a reference
/// reads the time base only under the lease it was taken under.
struct Installed {
    lease: u64,
    program: Option<Box<dyn ProgramTime>>,
}

/// How many wakers a word takes from the tables at a time, to wake once it has let go of their
/// lock: the batch lies on the stack of the caller.
const WAKE_BATCH: usize = 16;

/// A wait registered for a time.
struct Sleeper {
    id: u64,
    deadline_ns: u64,
    waker: Waker,
    /// Whether it lies in a slot a room set aside ([`TimeBaseRoom`]).
    roomed: bool,
}

/// A waker each word wakes, by the id its watch removes it by ([`MoveWatch`]).
struct Watcher {
    id: u64,
    waker: Waker,
    /// Whether it lies in a slot a room set aside ([`TimeBaseRoom`]).
    roomed: bool,
}

/// The slots the rooms of a time base set aside in one of its tables, and how many of them hold
/// an entry.
#[derive(Clone, Copy)]
struct Slots {
    set_aside: usize,
    taken: usize,
}

impl Slots {
    const NONE: Self = Self {
        set_aside: 0,
        taken: 0,
    };

    /// The slots set aside that hold no entry. A room let go of while a wait of it still waits
    /// leaves more taken than set aside until that wait ends, and none free.
    fn free(self) -> usize {
        self.set_aside.saturating_sub(self.taken)
    }

    fn take(&mut self) {
        self.taken += 1;
    }

    fn give(&mut self) {
        self.taken = self.taken.saturating_sub(1);
    }
}

/// The waits and the watches a time base holds. Each table's capacity is at least its length and
/// its free slots ([`Slots::free`]) together, so an entry of a room is placed with no allocation.
struct Sleepers {
    next_id: u64,
    /// In order of deadline, the latest first; of two with one deadline, the one registered first
    /// is nearer the end, and is woken first.
    waiting: Vec<Sleeper>,
    /// In order of id, which is the order they were made in.
    watching: Vec<Watcher>,
    wait_slots: Slots,
    watch_slots: Slots,
    /// The waits and watches refused for want of a slot, under the current lease.
    refused: u64,
}

/// Why a time base gave no room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomRefused {
    /// The heap refused the growth of the tables a reservation asked for; nothing was set aside.
    NoMemory,
    /// Every slot the rooms of the time base set aside holds an entry.
    Full,
}

/// The wakers taken from the tables under their lock, to wake after it.
struct WakeBatch {
    wakers: [Option<Waker>; WAKE_BATCH],
    len: usize,
}

impl WakeBatch {
    const fn new() -> Self {
        Self {
            wakers: [const { None }; WAKE_BATCH],
            len: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.len == WAKE_BATCH
    }

    /// Keep `waker`; the caller has seen the batch is not full.
    fn push(&mut self, waker: Waker) {
        self.wakers[self.len] = Some(waker);
        self.len += 1;
    }

    /// Wake every waker kept, in the order kept, and keep none.
    fn wake_all(&mut self) {
        for slot in &mut self.wakers[..self.len] {
            if let Some(waker) = slot.take() {
                waker.wake();
            }
        }
        self.len = 0;
    }
}

impl Sleepers {
    const fn new() -> Self {
        Self {
            next_id: 0,
            waiting: Vec::new(),
            watching: Vec::new(),
            wait_slots: Slots::NONE,
            watch_slots: Slots::NONE,
            refused: 0,
        }
    }

    /// An id no wait or watch of the time base has had, across leases too, so a wait or a watch
    /// of an earlier lease removes nothing of a later one.
    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Set aside `waits` slots of waits and `watches` of watches, the tables grown to hold them;
    /// `NoMemory`, with nothing set aside, when the heap refuses.
    fn set_aside(&mut self, waits: usize, watches: usize) -> Result<(), RoomRefused> {
        let wait_slots = Slots {
            set_aside: self
                .wait_slots
                .set_aside
                .checked_add(waits)
                .ok_or(RoomRefused::NoMemory)?,
            ..self.wait_slots
        };
        let watch_slots = Slots {
            set_aside: self
                .watch_slots
                .set_aside
                .checked_add(watches)
                .ok_or(RoomRefused::NoMemory)?,
            ..self.watch_slots
        };
        self.waiting
            .try_reserve(wait_slots.free())
            .map_err(|_| RoomRefused::NoMemory)?;
        self.watching
            .try_reserve(watch_slots.free())
            .map_err(|_| RoomRefused::NoMemory)?;
        self.wait_slots = wait_slots;
        self.watch_slots = watch_slots;
        Ok(())
    }

    /// Give back slots a room set aside. The tables keep their capacity, for the next room.
    fn give_back(&mut self, waits: usize, watches: usize) {
        self.wait_slots.set_aside = self.wait_slots.set_aside.saturating_sub(waits);
        self.watch_slots.set_aside = self.watch_slots.set_aside.saturating_sub(watches);
    }

    /// Place a wait for `deadline_ns` that `waker` wakes, in a free slot when `roomed`: its id, or
    /// `None`, counted, for a room with no slot free.
    fn place_wait(&mut self, deadline_ns: u64, waker: &Waker, roomed: bool) -> Option<u64> {
        if roomed {
            if self.wait_slots.free() == 0 {
                self.refused = self.refused.saturating_add(1);
                return None;
            }
            self.wait_slots.take();
        } else {
            // Room for this wait beside every free slot, so a wait of a room is still placed with
            // no allocation however many waits of none came before it.
            self.waiting.reserve(self.wait_slots.free() + 1);
        }
        let id = self.next_id();
        let at = self
            .waiting
            .partition_point(|entry| entry.deadline_ns > deadline_ns);
        self.waiting.insert(
            at,
            Sleeper {
                id,
                deadline_ns,
                waker: waker.clone(),
                roomed,
            },
        );
        Some(id)
    }

    /// Take the wait `id` names out of its table, if the table still holds it.
    fn remove_wait(&mut self, id: u64) -> Option<Sleeper> {
        let at = self.waiting.iter().position(|entry| entry.id == id)?;
        let sleeper = self.waiting.remove(at);
        if sleeper.roomed {
            self.wait_slots.give();
        }
        Some(sleeper)
    }

    /// Take the wait of the earliest deadline out of its table.
    fn pop_wait(&mut self) -> Option<Sleeper> {
        let sleeper = self.waiting.pop()?;
        if sleeper.roomed {
            self.wait_slots.give();
        }
        Some(sleeper)
    }

    /// Place a watch that `waker` is in a free slot of a room: its id, or `None`, counted, for a
    /// room with no slot free.
    fn place_watch_in_room(&mut self, waker: Waker) -> Option<u64> {
        if self.watch_slots.free() == 0 {
            self.refused = self.refused.saturating_add(1);
            return None;
        }
        self.watch_slots.take();
        Some(self.push_watch(waker, true))
    }

    /// Place a watch that `waker` is with no room, the table grown when it is full: its id.
    fn place_watch_on_heap(&mut self, waker: Waker) -> u64 {
        // Room for this watch beside every free slot, as for a wait of no room.
        self.watching.reserve(self.watch_slots.free() + 1);
        self.push_watch(waker, false)
    }

    /// Push a watch the table has the capacity for: its id.
    fn push_watch(&mut self, waker: Waker, roomed: bool) -> u64 {
        let id = self.next_id();
        self.watching.push(Watcher { id, waker, roomed });
        id
    }

    /// Take the watch `id` names out of its table, if the table still holds it.
    fn remove_watch(&mut self, id: u64) -> Option<Watcher> {
        let at = self.watching.iter().position(|entry| entry.id == id)?;
        let watcher = self.watching.remove(at);
        if watcher.roomed {
            self.watch_slots.give();
        }
        Some(watcher)
    }

    /// Take the watch made last out of its table.
    fn pop_watch(&mut self) -> Option<Watcher> {
        let watcher = self.watching.pop()?;
        if watcher.roomed {
            self.watch_slots.give();
        }
        Some(watcher)
    }

    /// Keep in `batch` the wakers of the watches made after the one `after` names (every watch
    /// for `None`), which stay, and then of the waits whose time has come by `now`, earliest first,
    /// which leave their table: whether the batch filled with some left for another.
    fn take_due(&mut self, now: u64, after: &mut Option<u64>, batch: &mut WakeBatch) -> bool {
        let from = (*after).map_or(0, |last| {
            self.watching.partition_point(|entry| entry.id <= last)
        });
        for watcher in &self.watching[from..] {
            if batch.is_full() {
                return true;
            }
            batch.push(watcher.waker.clone());
            *after = Some(watcher.id);
        }
        while self
            .waiting
            .last()
            .is_some_and(|last| last.deadline_ns <= now)
        {
            if batch.is_full() {
                return true;
            }
            if let Some(sleeper) = self.pop_wait() {
                batch.push(sleeper.waker);
            }
        }
        false
    }

    /// Keep in `batch` the wakers of every wait, earliest first, and then of every watch, each of
    /// which leaves its table: whether the batch filled with some left for another.
    fn take_all(&mut self, batch: &mut WakeBatch) -> bool {
        while !batch.is_full() {
            let next = match self.pop_wait() {
                Some(sleeper) => Some(sleeper.waker),
                None => self.pop_watch().map(|watcher| watcher.waker),
            };
            let Some(waker) = next else {
                return false;
            };
            batch.push(waker);
        }
        !self.waiting.is_empty() || !self.watching.is_empty()
    }
}

/// One time base, never freed (see "Holding").
struct TimeBase {
    installed: RwLock<Installed>,
    /// The highest reading given under the current lease, which a lower one is raised to.
    last_ns: AtomicU64,
    holders: AtomicUsize,
    sleepers: Mutex<Sleepers>,
}

/// The time bases no hold has, which the next one made is taken from, and how many were ever made.
struct Pool {
    free: Vec<&'static TimeBase>,
    made: usize,
}

impl Pool {
    /// A time base no hold has: a pooled one, or one made now with its place in the pool taken
    /// with it, so that its return ([`Self::give_back`]) never grows the pool.
    fn take(&mut self) -> &'static TimeBase {
        if let Some(base) = self.free.pop() {
            return base;
        }
        self.made += 1;
        // The pool is empty when nothing is popped, so this is a place for every base made.
        self.free.reserve(self.made);
        Box::leak(Box::new(TimeBase::new()))
    }

    /// Take back `base`, whose last hold went, into the place it was given when it was made: no
    /// memory is taken, though that hold may be a session's that took none once it opened.
    fn give_back(&mut self, base: &'static TimeBase) {
        self.free.push(base);
    }
}

/// The pool of every time base made.
static POOL: Mutex<Pool> = Mutex::new(Pool {
    free: Vec::new(),
    made: 0,
});

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock()
}

impl TimeBase {
    const fn new() -> Self {
        Self {
            installed: RwLock::new(Installed {
                lease: 0,
                program: None,
            }),
            last_ns: AtomicU64::new(0),
            holders: AtomicUsize::new(0),
            sleepers: Mutex::new(Sleepers::new()),
        }
    }

    /// Install `program` under a new lease, for its first hold; the lease.
    fn install(&self, program: Box<dyn ProgramTime>) -> u64 {
        locked(&self.sleepers).refused = 0;
        let mut installed = self.installed.write();
        installed.lease = installed.lease.wrapping_add(1);
        installed.program = Some(program);
        self.last_ns.store(0, Ordering::Release);
        self.holders.store(1, Ordering::Release);
        installed.lease
    }

    /// The time under `lease`: the program's reading held monotonic, or `u64::MAX` once the lease
    /// is over.
    fn now_ns(&self, lease: u64) -> u64 {
        let installed = self.installed.read();
        let Some(program) = installed
            .program
            .as_ref()
            .filter(|_| installed.lease == lease)
        else {
            return u64::MAX;
        };
        let now = program.now_ns();
        // Under the read lock, so that a retirement, which resets the mark under the write lock,
        // cannot come between this reading and the mark it raises.
        let last = self.last_ns.fetch_max(now, Ordering::AcqRel);
        last.max(now)
    }

    /// Wake every watch, and every wait whose time has come by the reading under `lease`, earliest
    /// first. The wakers run with no lock of the time base held: a woken task may poll at once on
    /// another thread.
    fn wake_due(&self, lease: u64) {
        let now = self.now_ns(lease);
        let mut after = None;
        let mut batch = WakeBatch::new();
        loop {
            let more = locked(&self.sleepers).take_due(now, &mut after, &mut batch);
            batch.wake_all();
            if !more {
                return;
            }
        }
    }

    /// Register a wait for `deadline_ns` that `waker` wakes, in a slot a room set aside when
    /// `roomed`, or give the wait `id` names this waker: the id of the wait, or `None` when the
    /// rooms have no slot free.
    fn register(
        &self,
        id: Option<u64>,
        deadline_ns: u64,
        waker: &Waker,
        roomed: bool,
    ) -> Option<u64> {
        let mut sleepers = locked(&self.sleepers);
        if let Some(id) = id {
            if let Some(entry) = sleepers.waiting.iter_mut().find(|entry| entry.id == id) {
                if !entry.waker.will_wake(waker) {
                    entry.waker = waker.clone();
                }
                return Some(id);
            }
        }
        sleepers.place_wait(deadline_ns, waker, roomed)
    }

    /// Remove the wait `id` names, if the time base still holds it; its waker goes after the lock.
    fn deregister(&self, id: u64) {
        let removed = locked(&self.sleepers).remove_wait(id);
        drop(removed);
    }

    /// Keep `waker` for every word from now on, the table grown when it is full: the id its watch
    /// removes it by.
    fn watch(&self, waker: Waker) -> u64 {
        locked(&self.sleepers).place_watch_on_heap(waker)
    }

    /// Keep `waker` for every word from now on, in a slot a room set aside: the id its watch
    /// removes it by, or `None` when the rooms have no slot free.
    fn watch_in_room(&self, waker: Waker) -> Option<u64> {
        locked(&self.sleepers).place_watch_in_room(waker)
    }

    /// Remove the watch `id` names, if the time base still holds it; its waker goes after the
    /// lock.
    fn unwatch(&self, id: u64) {
        let removed = locked(&self.sleepers).remove_watch(id);
        drop(removed);
    }

    /// End the lease: the program's read goes, with no lock of the time base held while its own
    /// drop runs, and every wait still registered is woken to read the time base as past its
    /// deadline. A watch is woken once more and let go: the base it watched is gone, and the next
    /// program's words are not its.
    fn retire(&self) {
        let program = {
            let mut installed = self.installed.write();
            installed.lease = installed.lease.wrapping_add(1);
            self.last_ns.store(0, Ordering::Release);
            installed.program.take()
        };
        drop(program);
        let mut batch = WakeBatch::new();
        loop {
            let more = locked(&self.sleepers).take_all(&mut batch);
            batch.wake_all();
            if !more {
                return;
            }
        }
    }
}

/// A hold of a time base: the program's, a configuration's or a session's. A clone is another
/// hold of the same time base; the program's read goes when the last hold does.
pub struct TimeBaseHold {
    base: &'static TimeBase,
    lease: u64,
}

impl TimeBaseHold {
    /// A time base that reads `program`, and the first hold of it.
    pub fn new(program: Box<dyn ProgramTime>) -> Self {
        let base = locked(&POOL).take();
        let lease = base.install(program);
        Self { base, lease }
    }

    /// The program's time, held monotonic, in nanoseconds.
    pub fn now_ns(&self) -> u64 {
        self.base.now_ns(self.lease)
    }

    /// The time base as a copyable reference, for a clock that must be one. It reads the time
    /// base only while a hold of it remains.
    pub fn time(&self) -> TimeBaseRef {
        TimeBaseRef {
            base: self.base,
            lease: self.lease,
        }
    }

    /// The program's time has moved on: every wait whose time has come by its reading now is
    /// woken, and every watch ([`Self::watch`]).
    pub fn advanced(&self) {
        self.base.wake_due(self.lease);
    }

    /// Wake `waker` at each word that the program's time moved on ([`Self::advanced`]), and once
    /// more when the last hold goes, until the watch returned is dropped: a thread that waits for
    /// input and for the time together (an engine's read) waits on what the waker makes ready.
    ///
    /// The watch takes no slot of a room: its table grows when it is full. A session that takes no
    /// memory after its open watches from the room it set aside ([`TimeBaseRoom::watch`]).
    pub fn watch(&self, waker: Waker) -> MoveWatch {
        MoveWatch {
            base: self.base,
            id: self.base.watch(waker),
        }
    }

    /// Set aside `waits` slots for waits and `watches` for watches, for a session that takes no
    /// memory once it is open: the time base's tables grow now, and every wait and every watch made
    /// from the room returned lies in one of its slots, until the room goes and gives them back.
    /// The room is a hold of the time base as well.
    ///
    /// `RoomRefused::NoMemory`, with nothing set aside, when the heap refuses the growth.
    pub fn reserve(&self, waits: usize, watches: usize) -> Result<TimeBaseRoom, RoomRefused> {
        locked(&self.base.sleepers).set_aside(waits, watches)?;
        Ok(TimeBaseRoom {
            hold: self.clone(),
            waits,
            watches,
        })
    }

    /// How many waits and watches the rooms of the time base had no slot for since its program was
    /// installed: each refused wait ended at once, and each refused watch was not made.
    pub fn refused(&self) -> u64 {
        locked(&self.base.sleepers).refused
    }
}

/// Slots a session set aside in a time base when it opened ([`TimeBaseHold::reserve`]), which its
/// waits and watches lie in, and a hold of the time base. The slots go back when this is dropped;
/// a wait of it still waiting keeps its slot until it ends.
pub struct TimeBaseRoom {
    hold: TimeBaseHold,
    waits: usize,
    watches: usize,
}

impl TimeBaseRoom {
    /// [`TimeBaseRef::sleep_until`] in a slot of this room: a wait that, when the room has no slot
    /// free as it is first polled, ends at once and is counted ([`TimeBaseHold::refused`]).
    pub fn sleep_until(&self, deadline_ns: u64) -> ProgramSleep {
        ProgramSleep {
            time: self.hold.time(),
            deadline_ns,
            registered: None,
            roomed: true,
        }
    }

    /// [`TimeBaseHold::watch`] in a slot of this room; `RoomRefused::Full`, counted, when the room
    /// has no slot free.
    pub fn watch(&self, waker: Waker) -> Result<MoveWatch, RoomRefused> {
        let id = self
            .hold
            .base
            .watch_in_room(waker)
            .ok_or(RoomRefused::Full)?;
        Ok(MoveWatch {
            base: self.hold.base,
            id,
        })
    }
}

impl Drop for TimeBaseRoom {
    fn drop(&mut self) {
        locked(&self.hold.base.sleepers).give_back(self.waits, self.watches);
    }
}

impl fmt::Debug for TimeBaseRoom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeBaseRoom")
            .field("waits", &self.waits)
            .field("watches", &self.watches)
            .finish_non_exhaustive()
    }
}

/// A waker the time base wakes at each word of the program's ([`TimeBaseHold::watch`]), kept
/// until this is dropped.
pub struct MoveWatch {
    base: &'static TimeBase,
    id: u64,
}

impl Drop for MoveWatch {
    fn drop(&mut self) {
        self.base.unwatch(self.id);
    }
}

impl fmt::Debug for MoveWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MoveWatch")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Clone for TimeBaseHold {
    fn clone(&self) -> Self {
        self.base.holders.fetch_add(1, Ordering::Relaxed);
        Self {
            base: self.base,
            lease: self.lease,
        }
    }
}

impl Drop for TimeBaseHold {
    fn drop(&mut self) {
        if self.base.holders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.base.retire();
            locked(&POOL).give_back(self.base);
        }
    }
}

/// Two holds are equal when they hold the same time base under the same lease.
impl PartialEq for TimeBaseHold {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.base, other.base) && self.lease == other.lease
    }
}

impl Eq for TimeBaseHold {}

impl fmt::Debug for TimeBaseHold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeBaseHold")
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

/// A copyable reference to a time base, taken from a hold ([`TimeBaseHold::time`]).
#[derive(Clone, Copy)]
pub struct TimeBaseRef {
    base: &'static TimeBase,
    lease: u64,
}

impl TimeBaseRef {
    /// The program's time, held monotonic, in nanoseconds; `u64::MAX` once no hold of the time
    /// base it was taken from remains.
    pub fn now_ns(&self) -> u64 {
        self.base.now_ns(self.lease)
    }

    /// A wait that ends when the program's time reaches `deadline_ns` and the program says so
    /// ([`TimeBaseHold::advanced`]), or at once when it has already. It takes no slot of a room:
    /// its table grows when it is full ([`TimeBaseRoom::sleep_until`] is the wait that does not).
    pub fn sleep_until(&self, deadline_ns: u64) -> ProgramSleep {
        ProgramSleep {
            time: *self,
            deadline_ns,
            registered: None,
            roomed: false,
        }
    }
}

impl fmt::Debug for TimeBaseRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeBaseRef")
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

/// A wait for a time of the program's ([`TimeBaseRef::sleep_until`]).
pub struct ProgramSleep {
    time: TimeBaseRef,
    deadline_ns: u64,
    /// The wait the time base holds for this one, once it has been polled and not ended.
    registered: Option<u64>,
    /// Whether it lies in a slot a room set aside ([`TimeBaseRoom::sleep_until`]).
    roomed: bool,
}

impl ProgramSleep {
    /// Whether the time has come.
    fn due(&self) -> bool {
        self.time.now_ns() >= self.deadline_ns
    }

    /// The time base lets go of this wait.
    fn forget(&mut self) {
        if let Some(id) = self.registered.take() {
            self.time.base.deregister(id);
        }
    }
}

impl Future for ProgramSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.due() {
            this.forget();
            return Poll::Ready(());
        }
        this.registered =
            this.time
                .base
                .register(this.registered, this.deadline_ns, cx.waker(), this.roomed);
        // A room with no slot free: the wait ends at once, and the time base counted it.
        if this.registered.is_none() {
            return Poll::Ready(());
        }
        // Read again: a program that moved its time and said so between the first reading and the
        // registration found no wait to wake, and its time is seen here.
        if this.due() {
            this.forget();
            return Poll::Ready(());
        }
        Poll::Pending
    }
}

impl Drop for ProgramSleep {
    fn drop(&mut self) {
        self.forget();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::task::Wake;

    thread_local! {
        static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    }

    /// The lib test binary's allocator: `System`'s, each allocation counted on the thread that
    /// made it, so a test reads what its own calls took and none of the tests beside it.
    struct Counting;

    // SAFETY: every call forwards to `System` unchanged; the count is a thread-local cell with no
    // destructor, which neither allocates nor unwinds.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOCATIONS.with(|n| n.set(n.get() + 1));
            // SAFETY: the caller's contract, forwarded.
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            ALLOCATIONS.with(|n| n.set(n.get() + 1));
            // SAFETY: the caller's contract, forwarded.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            ALLOCATIONS.with(|n| n.set(n.get() + 1));
            // SAFETY: the caller's contract, forwarded.
            unsafe { System.realloc(ptr, layout, new_size) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: the caller's contract, forwarded.
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static COUNTING: Counting = Counting;

    /// How many allocations the calling thread has made.
    fn allocations() -> usize {
        ALLOCATIONS.with(Cell::get)
    }

    /// The program's time as the test sets it.
    struct SetTime(Arc<AtomicU64>);

    impl ProgramTime for SetTime {
        fn now_ns(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// A program's time that stands at seven and counts how often its read was let go of.
    struct CountsDrops(Arc<AtomicUsize>);

    impl ProgramTime for CountsDrops {
        fn now_ns(&self) -> u64 {
            7
        }
    }

    impl Drop for CountsDrops {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A waker that counts how often it was woken.
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn time_at(ns: u64) -> (Arc<AtomicU64>, TimeBaseHold) {
        let now = Arc::new(AtomicU64::new(ns));
        let hold = TimeBaseHold::new(Box::new(SetTime(now.clone())));
        (now, hold)
    }

    fn wakes() -> (Arc<Wakes>, Waker) {
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        (wakes, waker)
    }

    fn poll(sleep: &mut ProgramSleep, waker: &Waker) -> Poll<()> {
        Pin::new(sleep).poll(&mut Context::from_waker(waker))
    }

    #[test]
    fn the_time_is_the_programs_and_never_goes_back() {
        let (now, hold) = time_at(5_000);
        assert_eq!(hold.now_ns(), 5_000);
        now.store(9_000, Ordering::SeqCst);
        assert_eq!(hold.time().now_ns(), 9_000);
        now.store(6_000, Ordering::SeqCst);
        assert_eq!(
            hold.now_ns(),
            9_000,
            "a reading below one already given is the one given"
        );
        now.store(12_000, Ordering::SeqCst);
        assert_eq!(hold.now_ns(), 12_000);
    }

    #[test]
    fn a_wait_ends_when_the_programs_time_reaches_it_and_the_program_says_so() {
        let (now, hold) = time_at(0);
        let (wakes, waker) = wakes();
        let mut sleep = hold.time().sleep_until(1_000);
        assert!(poll(&mut sleep, &waker).is_pending());

        // Short of the deadline and told: nothing is woken.
        now.store(999, Ordering::SeqCst);
        hold.advanced();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

        // At the deadline and not told: nothing is woken either.
        now.store(1_000, Ordering::SeqCst);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

        // Told: the wait is woken once, and ends.
        hold.advanced();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert!(poll(&mut sleep, &waker).is_ready());
        hold.advanced();
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            1,
            "an ended wait is not held any more"
        );
    }

    #[test]
    fn a_wait_whose_time_has_already_come_ends_without_being_told() {
        let (now, hold) = time_at(0);
        let (wakes, waker) = wakes();
        now.store(50, Ordering::SeqCst);
        let mut sleep = hold.time().sleep_until(50);
        assert!(poll(&mut sleep, &waker).is_ready());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_dropped_wait_is_not_woken() {
        let (now, hold) = time_at(0);
        let (wakes, waker) = wakes();
        let mut sleep = hold.time().sleep_until(10);
        assert!(poll(&mut sleep, &waker).is_pending());
        drop(sleep);
        now.store(10, Ordering::SeqCst);
        hold.advanced();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_programs_read_goes_with_the_last_hold_and_ends_what_still_waits() {
        let drops = Arc::new(AtomicUsize::new(0));
        let hold = TimeBaseHold::new(Box::new(CountsDrops(drops.clone())));
        let other = hold.clone();
        assert_eq!(hold, other);
        let time = hold.time();
        let (wakes, waker) = wakes();
        let mut sleep = time.sleep_until(1_000);
        assert!(poll(&mut sleep, &waker).is_pending());

        drop(hold);
        assert_eq!(drops.load(Ordering::SeqCst), 0, "a hold remains");
        assert_eq!(time.now_ns(), 7);

        drop(other);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "the last hold let the read go"
        );
        assert_eq!(
            time.now_ns(),
            u64::MAX,
            "a reference past its holds reads past every deadline"
        );
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            1,
            "the wait still held was let go"
        );
        assert!(poll(&mut sleep, &waker).is_ready());
    }

    /// A watch is woken at each word whatever the time, until it is dropped, and once more when
    /// the last hold goes. CONTROL: before any word it is not woken. Turned red by a word that
    /// wakes no watch, a watch woken after it was dropped, or one the end of the base forgets.
    #[test]
    fn a_watch_is_woken_at_each_word_until_it_is_dropped() {
        let (_now, hold) = time_at(0);
        let (woken, waker) = wakes();
        let watch = hold.watch(waker);
        assert_eq!(woken.0.load(Ordering::SeqCst), 0, "CONTROL: no word yet");
        hold.advanced();
        hold.advanced();
        assert_eq!(
            woken.0.load(Ordering::SeqCst),
            2,
            "each word woke the watch, with no wait due"
        );
        drop(watch);
        hold.advanced();
        assert_eq!(
            woken.0.load(Ordering::SeqCst),
            2,
            "a dropped watch is woken no more"
        );

        let (kept_wakes, kept) = wakes();
        let _kept = hold.watch(kept);
        drop(hold);
        assert_eq!(
            kept_wakes.0.load(Ordering::SeqCst),
            1,
            "the last hold's going woke the watch"
        );
    }

    /// A waker that writes its name into a log shared by several, in the order they are woken.
    struct Logs {
        name: u64,
        log: Arc<StdMutex<Vec<u64>>>,
    }

    impl Wake for Logs {
        fn wake(self: Arc<Self>) {
            self.log.lock().unwrap().push(self.name);
        }
    }

    /// Once a room is set aside, words take no memory, however many waits they end and watches
    /// they wake: the waits are taken in place and the wakers woken from a batch on the stack.
    /// CONTROL: a wait of no room grows its table when it is full. Turned red by a word that
    /// gathers the wakers it wakes into a new vector, or a wait of a room that grows its table.
    #[test]
    fn words_take_no_memory_once_a_room_is_set_aside() {
        const WAITS: usize = 4;
        let (now, hold) = time_at(0);
        let room = hold.reserve(WAITS, 1).expect("the heap gives the room");
        let (watched, watcher) = wakes();
        let _watch = room.watch(watcher).expect("the room has its watch");
        let (_ended, waker) = wakes();
        let mut sleeps: Vec<ProgramSleep> = (1..=WAITS as u64)
            .map(|at| room.sleep_until(1_000 * at))
            .collect();
        // Warm the calls once, so what a first call makes of the thread's own is not counted.
        hold.advanced();
        let before = allocations();
        for round in 1..=100u64 {
            for sleep in &mut sleeps {
                let _ = poll(sleep, &waker);
            }
            now.store(round * 500, Ordering::SeqCst);
            hold.advanced();
        }
        assert_eq!(
            allocations() - before,
            0,
            "a word after the room took memory"
        );
        assert!(
            sleeps
                .iter_mut()
                .all(|sleep| poll(sleep, &waker).is_ready()),
            "every wait of the room ended"
        );
        assert_eq!(
            watched.0.load(Ordering::SeqCst),
            101,
            "each word woke the watch"
        );
        assert_eq!(hold.refused(), 0, "the room had a slot for each");

        // CONTROL: a wait of no room, past the capacity the table has, takes memory.
        let mut filled: Vec<ProgramSleep> =
            (0..64).map(|_| hold.time().sleep_until(u64::MAX)).collect();
        let before = allocations();
        for sleep in &mut filled {
            assert!(poll(sleep, &waker).is_pending());
        }
        assert!(
            allocations() > before,
            "CONTROL: a wait of no room grows its table"
        );
    }

    /// A room's waits and watches past its slots are refused and counted, with no memory taken: a
    /// refused wait ends at once, a refused watch is not made, and a slot given back is taken
    /// again. A reservation the heap cannot give sets nothing aside. Turned red by a wait or a
    /// watch of a full room that grows its table, or a refusal left uncounted.
    #[test]
    fn a_rooms_wait_or_watch_past_its_slots_is_refused_and_counted() {
        let (now, hold) = time_at(0);
        assert_eq!(
            hold.reserve(usize::MAX, 0).err(),
            Some(RoomRefused::NoMemory),
            "the heap cannot give a room of every slot"
        );
        let room = hold.reserve(1, 1).expect("the heap gives the room");
        let (woken, waker) = wakes();
        let first = room.watch(waker.clone()).expect("the room's one watch");
        let mut waiting = room.sleep_until(1_000);
        assert!(
            poll(&mut waiting, &waker).is_pending(),
            "the room's one wait"
        );

        let before = allocations();
        assert_eq!(room.watch(waker.clone()).err(), Some(RoomRefused::Full));
        let mut refused = room.sleep_until(1_000);
        assert!(
            poll(&mut refused, &waker).is_ready(),
            "a wait the room has no slot for ends at once"
        );
        assert_eq!(allocations() - before, 0, "a refusal took memory");
        assert_eq!(hold.refused(), 2, "both refusals are counted");

        // The slots given back are taken again.
        drop(first);
        let _again = room
            .watch(waker.clone())
            .expect("the slot the dropped watch gave back");
        now.store(1_000, Ordering::SeqCst);
        hold.advanced();
        assert!(poll(&mut waiting, &waker).is_ready());
        let mut next = room.sleep_until(2_000);
        assert!(
            poll(&mut next, &waker).is_pending(),
            "the slot the ended wait gave back"
        );
        assert_eq!(hold.refused(), 2);
        assert!(woken.0.load(Ordering::SeqCst) >= 1);
    }

    /// A word ends the waits whose time has come earliest first, and of two with one deadline the
    /// one registered first; a wait whose time has not come stays. Turned red by a table kept in
    /// the order the waits came, or a tie put before the waits of its deadline already there.
    #[test]
    fn a_word_ends_the_waits_earliest_deadline_first() {
        let (now, hold) = time_at(0);
        let log = Arc::new(StdMutex::new(Vec::new()));
        let mut sleeps: Vec<(ProgramSleep, Waker)> = [(1, 30), (2, 10), (3, 20), (4, 10), (5, 40)]
            .into_iter()
            .map(|(name, deadline)| {
                let waker = Waker::from(Arc::new(Logs {
                    name,
                    log: log.clone(),
                }));
                (hold.time().sleep_until(deadline), waker)
            })
            .collect();
        for (sleep, waker) in &mut sleeps {
            assert!(poll(sleep, waker).is_pending());
        }
        now.store(30, Ordering::SeqCst);
        hold.advanced();
        assert_eq!(*log.lock().unwrap(), vec![2, 4, 3, 1]);
        now.store(40, Ordering::SeqCst);
        hold.advanced();
        assert_eq!(*log.lock().unwrap(), vec![2, 4, 3, 1, 5]);
    }

    /// One word wakes every watch and ends every wait due, more than one batch holds of each, each
    /// once. Turned red by a word that stops at its first batch, or one that wakes a watch twice
    /// as it resumes.
    #[test]
    fn a_word_wakes_more_than_one_batch_each_once() {
        let many = 3 * WAKE_BATCH + 1;
        let (now, hold) = time_at(0);
        let (watched, watcher) = wakes();
        let _watches: Vec<MoveWatch> = (0..many).map(|_| hold.watch(watcher.clone())).collect();
        let (ended, waker) = wakes();
        let mut sleeps: Vec<ProgramSleep> = (0..many).map(|_| hold.time().sleep_until(5)).collect();
        for sleep in &mut sleeps {
            assert!(poll(sleep, &waker).is_pending());
        }
        now.store(5, Ordering::SeqCst);
        hold.advanced();
        assert_eq!(watched.0.load(Ordering::SeqCst), many, "every watch, once");
        assert_eq!(ended.0.load(Ordering::SeqCst), many, "every wait due, once");
    }

    /// The last hold of a time base goes with no memory taken, however many go at once: each base
    /// has its place in the pool from when it was made. Turned red by a pool that grows as a base
    /// comes back to it.
    #[test]
    fn the_last_holds_go_back_to_the_pool_with_no_memory_taken() {
        // More bases than every other test of the binary holds, so a pool that grew as they came
        // back would grow here whatever ran before.
        const BASES: u64 = 64;
        let holds: Vec<TimeBaseHold> = (0..BASES).map(|ns| time_at(ns).1).collect();
        assert!(
            holds.iter().all(|hold| hold.now_ns() < BASES),
            "CONTROL: every hold reads its own program"
        );
        let before = allocations();
        drop(holds);
        assert_eq!(
            allocations() - before,
            0,
            "a base's return to the pool took memory"
        );
    }

    #[test]
    fn a_reference_of_an_earlier_lease_does_not_read_the_next_programs_time() {
        // A base of the test's own, so no other test's hold takes it from the pool between the
        // two leases.
        let base: &'static TimeBase = Box::leak(Box::new(TimeBase::new()));
        let first = base.install(Box::new(SetTime(Arc::new(AtomicU64::new(3)))));
        assert_eq!(base.now_ns(first), 3);
        base.retire();
        let second = base.install(Box::new(SetTime(Arc::new(AtomicU64::new(40)))));
        assert_ne!(first, second);
        assert_eq!(base.now_ns(second), 40);
        assert_eq!(base.now_ns(first), u64::MAX);
    }
}

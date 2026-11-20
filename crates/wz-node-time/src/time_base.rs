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
//! waits until it is told.
//!
//! ## Holding
//!
//! A time base is held ([`TimeBaseHold`]) by the program, by each configuration that names it and
//! by each session opened on it, and the program's read goes when the last of them does. An engine
//! whose clock is a copyable value reads it through a [`TimeBaseRef`], beside a hold kept for as
//! long as its session is. The time base itself is never freed: when its last hold goes it returns
//! to a pool a later one is taken from, so a reference never dangles, and a reference that
//! outlives the holds it was taken under reads the time base as past every deadline. Whatever
//! still waits on it then ends, and nothing reads another program's time through it.

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock};

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

/// A wait registered for a time.
struct Sleeper {
    id: u64,
    deadline_ns: u64,
    waker: Waker,
}

/// The waits a time base holds.
struct Sleepers {
    next_id: u64,
    waiting: Vec<Sleeper>,
}

/// One time base, never freed (see "Holding").
struct TimeBase {
    installed: RwLock<Installed>,
    /// The highest reading given under the current lease, which a lower one is raised to.
    last_ns: AtomicU64,
    holders: AtomicUsize,
    sleepers: Mutex<Sleepers>,
}

/// The time bases no hold has, which the next one made is taken from.
static POOL: Mutex<Vec<&'static TimeBase>> = Mutex::new(Vec::new());

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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
            sleepers: Mutex::new(Sleepers {
                next_id: 0,
                waiting: Vec::new(),
            }),
        }
    }

    /// Install `program` under a new lease, for its first hold; the lease.
    fn install(&self, program: Box<dyn ProgramTime>) -> u64 {
        let mut installed = self
            .installed
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        installed.lease = installed.lease.wrapping_add(1);
        installed.program = Some(program);
        self.last_ns.store(0, Ordering::Release);
        self.holders.store(1, Ordering::Release);
        installed.lease
    }

    /// The time under `lease`: the program's reading held monotonic, or `u64::MAX` once the lease
    /// is over.
    fn now_ns(&self, lease: u64) -> u64 {
        let installed = self
            .installed
            .read()
            .unwrap_or_else(PoisonError::into_inner);
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

    /// Wake every wait whose time has come by the reading under `lease`. The wakers run with no
    /// lock of the time base held: a woken task may poll at once on another thread.
    fn wake_due(&self, lease: u64) {
        let now = self.now_ns(lease);
        let due = {
            let mut sleepers = locked(&self.sleepers);
            let mut due = Vec::new();
            let mut at = 0;
            while at < sleepers.waiting.len() {
                if sleepers.waiting[at].deadline_ns <= now {
                    due.push(sleepers.waiting.swap_remove(at).waker);
                } else {
                    at += 1;
                }
            }
            due
        };
        for waker in due {
            waker.wake();
        }
    }

    /// Register a wait for `deadline_ns` that `waker` wakes, or give the wait `id` names this
    /// waker; the id of the wait.
    fn register(&self, id: Option<u64>, deadline_ns: u64, waker: &Waker) -> u64 {
        let mut sleepers = locked(&self.sleepers);
        if let Some(id) = id {
            if let Some(entry) = sleepers.waiting.iter_mut().find(|entry| entry.id == id) {
                if !entry.waker.will_wake(waker) {
                    entry.waker = waker.clone();
                }
                return id;
            }
        }
        let id = sleepers.next_id;
        sleepers.next_id = sleepers.next_id.wrapping_add(1);
        sleepers.waiting.push(Sleeper {
            id,
            deadline_ns,
            waker: waker.clone(),
        });
        id
    }

    /// Remove the wait `id` names, if the time base still holds it.
    fn deregister(&self, id: u64) {
        let mut sleepers = locked(&self.sleepers);
        sleepers.waiting.retain(|entry| entry.id != id);
    }

    /// End the lease: the program's read goes, with no lock of the time base held while its own
    /// drop runs, and every wait still registered is woken to read the time base as past its
    /// deadline.
    fn retire(&self) {
        let program = {
            let mut installed = self
                .installed
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            installed.lease = installed.lease.wrapping_add(1);
            self.last_ns.store(0, Ordering::Release);
            installed.program.take()
        };
        drop(program);
        let waiting = core::mem::take(&mut locked(&self.sleepers).waiting);
        for sleeper in waiting {
            sleeper.waker.wake();
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
        let base = locked(&POOL)
            .pop()
            .unwrap_or_else(|| &*Box::leak(Box::new(TimeBase::new())));
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
    /// woken.
    pub fn advanced(&self) {
        self.base.wake_due(self.lease);
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
            locked(&POOL).push(self.base);
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
    /// ([`TimeBaseHold::advanced`]), or at once when it has already.
    pub fn sleep_until(&self, deadline_ns: u64) -> ProgramSleep {
        ProgramSleep {
            time: *self,
            deadline_ns,
            registered: None,
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
        this.registered = Some(this.time.base.register(
            this.registered,
            this.deadline_ns,
            cx.waker(),
        ));
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
    use std::sync::Arc;
    use std::task::Wake;

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

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The callback a row of the session's tables owns, and the latch that says when it may be let go
//! (`docs/c-abi-architecture.md`, P11).
//!
//! A call of a row's callback is begun while the tables are held ([`RowCallback::begin`]), made
//! after they are let go, so the callback may declare and undeclare on the session it is called
//! by, and ended without taking them again ([`RowCallback::end`]). Undeclaring the row retires
//! it ([`RowCallback::retire`]): no call begins after that, and the row is let go of, with its
//! callback, by whoever sees the last call end: the undeclarer when none runs, else the call that
//! ends last. The count of calls running and the retirement are one word kept in the row
//! ([`CallLatch`]): ending a call is one atomic operation and no allocation, or, on a target with no
//! atomic read-modify-write of the word, a count changed with the tables held.
//!
//! Two forms implement [`RowCallback`]: the three values of a C closure, called where the row lies
//! ([`CClosure`]), and, in a heap build, a Rust closure shared with the calls of it
//! (`ArcCallback`).

use core::ffi::c_void;
use core::ptr::NonNull;

/// Set in a latch once its row is retired.
const RETIRED: u32 = 0x8000_0000;
/// The count of calls running, below [`RETIRED`].
const CALLS: u32 = !RETIRED;

/// The word a latch counts in, read and changed as one step.
trait Word {
    /// The word now.
    fn load(&self) -> u32;
    /// Set the word to `next(now)` when that is `Some`, as one step: the word before, `Ok` when it
    /// was changed.
    fn update(&self, next: impl FnMut(u32) -> Option<u32>) -> Result<u32, u32>;
}

/// The word where the target has an atomic read-modify-write of it: a call may end with no lock.
#[cfg(target_has_atomic = "32")]
#[derive(Debug, Default)]
struct AtomicWord(core::sync::atomic::AtomicU32);

#[cfg(target_has_atomic = "32")]
impl Word for AtomicWord {
    fn load(&self) -> u32 {
        self.0.load(core::sync::atomic::Ordering::Acquire)
    }

    fn update(&self, next: impl FnMut(u32) -> Option<u32>) -> Result<u32, u32> {
        use core::sync::atomic::Ordering;
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, next)
    }
}

/// The word where the target has no atomic read-modify-write of it (ARMv6-M): changed only with
/// the tables held, whose lock is the target's critical section, so every step is one already.
#[cfg(any(not(target_has_atomic = "32"), test))]
#[derive(Debug, Default)]
struct HeldWord(core::cell::Cell<u32>);

#[cfg(any(not(target_has_atomic = "32"), test))]
impl Word for HeldWord {
    fn load(&self) -> u32 {
        self.0.get()
    }

    fn update(&self, mut next: impl FnMut(u32) -> Option<u32>) -> Result<u32, u32> {
        let now = self.0.get();
        match next(now) {
            Some(changed) => {
                self.0.set(changed);
                Ok(now)
            }
            None => Err(now),
        }
    }
}

/// The latch's rules, over either word.
#[derive(Debug, Default)]
struct Counter<W>(W);

impl<W: Word> Counter<W> {
    fn begin(&self) -> bool {
        self.0
            .update(|now| {
                (now & RETIRED == 0 && now & CALLS != CALLS).then_some(now.wrapping_add(1))
            })
            .is_ok()
    }

    fn end(&self) -> bool {
        self.0.update(|now| Some(now.wrapping_sub(1))) == Ok(RETIRED | 1)
    }

    fn retire(&self) -> bool {
        self.0
            .update(|now| Some(now | RETIRED))
            .is_ok_and(|before| before & CALLS == 0)
    }

    fn drained(&self) -> bool {
        self.0.load() == RETIRED
    }
}

/// The word of this target.
#[cfg(target_has_atomic = "32")]
type TargetWord = AtomicWord;
/// The word of this target.
#[cfg(not(target_has_atomic = "32"))]
type TargetWord = HeldWord;

/// How many calls of a row's callback run, and whether the row was retired, in one word: atomic
/// where the target has an atomic read-modify-write of it, so a call ends with no lock; else
/// a plain count changed only with the tables held ([`Self::ENDS_HELD`]).
#[derive(Debug, Default)]
pub struct CallLatch(Counter<TargetWord>);

impl CallLatch {
    /// Whether a call is ended with the tables held: on a target with no atomic read-modify-write
    /// of the word, whose count the tables' lock guards.
    pub const ENDS_HELD: bool = cfg!(not(target_has_atomic = "32"));

    /// No call running, not retired.
    pub const fn new() -> Self {
        #[cfg(target_has_atomic = "32")]
        let word = AtomicWord(core::sync::atomic::AtomicU32::new(0));
        #[cfg(not(target_has_atomic = "32"))]
        let word = HeldWord(core::cell::Cell::new(0));
        Self(Counter(word))
    }

    /// Count one more call: `false` once the row is retired, and past the most calls one word
    /// counts.
    pub fn begin(&self) -> bool {
        self.0.begin()
    }

    /// Count one call fewer: `true` when it was the last call of a retired row, whose letting go
    /// is then the caller's. Called once for each [`Self::begin`] that returned `true`, with the
    /// tables held where [`Self::ENDS_HELD`].
    pub fn end(&self) -> bool {
        self.0.end()
    }

    /// Retire the row: no call begins from here. `true` when no call runs, so the row may be let
    /// go of now; else the call that ends last says so ([`Self::end`]). Called once.
    pub fn retire(&self) -> bool {
        self.0.retire()
    }

    /// Whether the row is retired and no call of it runs.
    pub fn drained(&self) -> bool {
        self.0.drained()
    }
}

/// A row's callback as the tables call it.
pub trait RowCallback {
    /// What a call is made with once the tables are let go.
    type Call;

    /// Whether a call reads the row where it lies, so a table may hold this form only where its
    /// rows never move (a table whose storage is fixed or lent, not one that grows).
    const READS_ROW_IN_PLACE: bool;

    /// Begin a call, with the tables held: `None` once the row is retired.
    fn begin(&self) -> Option<Self::Call>;

    /// End a call: `true` when it was the last call of a retired row, which the caller then takes
    /// out of its table and lets go of.
    ///
    /// # Safety
    ///
    /// `call` was begun on a row that has not moved since, where [`Self::READS_ROW_IN_PLACE`]
    /// says a call reads it: a row is let go of only once its last call ended, so it is still in
    /// its table. Where [`CallLatch::ENDS_HELD`] the tables are held, as they were at the begin.
    unsafe fn end(call: Self::Call) -> bool;

    /// Retire the row, with the tables held: `true` when no call of it runs, so it may be let go
    /// of now.
    fn retire(&self) -> bool;
}

/// What a C closure's `drop` is.
pub type CDrop = unsafe extern "C" fn(*mut c_void);

/// A callback the tables call only while they are held (a sink a fan hands `&mut` under the lock),
/// or a row that holds none: no call of it outlives the tables' hold, so its row is let go of when
/// it is undeclared.
macro_rules! called_while_held {
    ($($ty:ty),* $(,)?) => {$(
        impl RowCallback for $ty {
            type Call = core::convert::Infallible;

            const READS_ROW_IN_PLACE: bool = false;

            fn begin(&self) -> Option<core::convert::Infallible> {
                None
            }

            unsafe fn end(call: core::convert::Infallible) -> bool {
                match call {}
            }

            fn retire(&self) -> bool {
                true
            }
        }
    )*};
}

called_while_held!(());
#[cfg(feature = "alloc")]
called_while_held!(crate::sink::BoxedSink);
#[cfg(feature = "storage-profile")]
called_while_held!(crate::slot_observer::NoSink);

/// The three values of a C closure (`call`, `context`, `drop`) and the latch of its calls, held
/// by a row where it lies: the form a C program's callback takes in the tables, with no
/// allocation. `Call` is the door's function pointer type, called by the door with arguments of
/// its ABI; `drop(context)` runs once, when the row is let go of, after its last call.
///
/// Neither `Send` nor `Sync`: whether a C program's context may be used from another thread is
/// the program's, so a door that hands a closure to the tables of several threads wraps it in a
/// type of its own and states why that is sound.
pub struct CClosure<Call: Copy> {
    call: Call,
    context: *mut c_void,
    drop: Option<CDrop>,
    latch: CallLatch,
}

impl<Call: Copy> CClosure<Call> {
    /// The closure `call`, `context`, `drop`.
    ///
    /// # Safety
    ///
    /// `call` and `drop` may be called with `context`, the first from any call the tables begin
    /// and the second once, after every call: what the program's closure promises.
    pub const unsafe fn new(call: Call, context: *mut c_void, drop: Option<CDrop>) -> Self {
        Self {
            call,
            context,
            drop,
            latch: CallLatch::new(),
        }
    }
}

impl<Call: Copy> Drop for CClosure<Call> {
    fn drop(&mut self) {
        if let Some(drop) = self.drop.take() {
            // SAFETY: `new`'s contract: `drop` is called once, with `context`, after every call;
            // the row this closure is in is let go of only after its last call ended.
            unsafe { drop(self.context) };
        }
    }
}

/// A call of a [`CClosure`]: what the door calls, and where the latch the call ends on lies.
pub struct CCall<Call> {
    /// The closure's `call`.
    pub call: Call,
    /// The closure's `context`.
    pub context: *mut c_void,
    latch: NonNull<CallLatch>,
}

impl<Call: Copy> RowCallback for CClosure<Call> {
    type Call = CCall<Call>;

    const READS_ROW_IN_PLACE: bool = true;

    fn begin(&self) -> Option<CCall<Call>> {
        self.latch.begin().then(|| CCall {
            call: self.call,
            context: self.context,
            latch: NonNull::from(&self.latch),
        })
    }

    unsafe fn end(call: CCall<Call>) -> bool {
        // SAFETY: the caller's: the row the latch is in has not moved and is not let go of before
        // this call ends.
        unsafe { call.latch.as_ref() }.end()
    }

    fn retire(&self) -> bool {
        self.latch.retire()
    }
}

/// A Rust closure and the latch of its calls, shared with every call of it: the form a callback of
/// a heap build takes, whose table may move its rows while a call runs.
#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
pub struct ArcCallback<F>(alloc::sync::Arc<Shared<F>>);

/// What an [`ArcCallback`] and its calls share.
#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
pub struct Shared<F> {
    latch: CallLatch,
    callback: F,
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl<F> Shared<F> {
    /// The closure.
    pub fn callback(&self) -> &F {
        &self.callback
    }
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl<F> ArcCallback<F> {
    /// `callback`, with no call running.
    pub fn new(callback: F) -> Self {
        Self(alloc::sync::Arc::new(Shared {
            latch: CallLatch::new(),
            callback,
        }))
    }
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl<F> RowCallback for ArcCallback<F> {
    type Call = alloc::sync::Arc<Shared<F>>;

    const READS_ROW_IN_PLACE: bool = false;

    fn begin(&self) -> Option<Self::Call> {
        self.0
            .latch
            .begin()
            .then(|| alloc::sync::Arc::clone(&self.0))
    }

    unsafe fn end(call: Self::Call) -> bool {
        call.latch.end()
    }

    fn retire(&self) -> bool {
        self.0.latch.retire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End `call`, begun on `row`.
    fn ended<R: RowCallback>(_row: &R, call: R::Call) -> bool {
        // SAFETY: every row these tests end a call of stays where it was when the call began.
        unsafe { R::end(call) }
    }

    /// A retired latch begins no call, and exactly one party is told it may let the row go: the
    /// retirer when no call ran, else the call that ends last. The same rules over the atomic word
    /// and the held one.
    fn the_last_to_leave_a_retired_row_lets_it_go<W: Word + Default>() {
        let idle = Counter::<W>::default();
        assert!(idle.retire(), "no call runs: the retirer lets it go");
        assert!(idle.drained());
        assert!(!idle.begin(), "a retired row begins no call");

        let busy = Counter::<W>::default();
        assert!(busy.begin() && busy.begin());
        assert!(!busy.retire(), "two calls run: not the retirer's");
        assert!(!busy.drained());
        assert!(!busy.end(), "one call still runs");
        assert!(busy.end(), "the last call of a retired row lets it go");
        assert!(busy.drained());

        let live = Counter::<W>::default();
        assert!(live.begin());
        assert!(!live.end(), "a live row is let go of by nobody");
    }

    #[cfg(target_has_atomic = "32")]
    #[test]
    fn the_atomic_latch_lets_a_retired_row_go_at_its_last_call() {
        the_last_to_leave_a_retired_row_lets_it_go::<AtomicWord>();
    }

    #[test]
    fn the_held_latch_lets_a_retired_row_go_at_its_last_call() {
        the_last_to_leave_a_retired_row_lets_it_go::<HeldWord>();
    }

    /// The C form hands a call its `call` and `context`, and runs `drop(context)` once, when it
    /// is let go of.
    #[test]
    fn a_c_closure_is_called_with_its_context_and_dropped_once() {
        use core::sync::atomic::AtomicUsize;
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn count(_context: *mut c_void) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
        let mut context = 7u8;
        let context = core::ptr::addr_of_mut!(context).cast::<c_void>();
        // SAFETY: `count` reads nothing through the context, and the call is a number.
        let closure = unsafe { CClosure::new(3u8, context, Some(count)) };
        let call = closure.begin().expect("live");
        assert_eq!((call.call, call.context), (3, context));
        assert!(!closure.retire(), "a call runs");
        assert!(closure.begin().is_none());
        assert!(ended(&closure, call));
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            0,
            "dropped only when let go of"
        );
        drop(closure);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    }

    /// The Rust form's call holds the closure itself, so the row may move while it runs.
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    #[test]
    fn a_rust_closures_call_holds_the_closure() {
        let row = ArcCallback::new(|x: u32| x + 1);
        let call = row.begin().expect("live");
        let moved = row;
        assert_eq!((call.callback())(1), 2);
        assert!(!moved.retire());
        assert!(ended(&moved, call));
    }
}

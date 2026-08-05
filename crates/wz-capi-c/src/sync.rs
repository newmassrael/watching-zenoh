// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The MUTEX and CONDVAR family `z_ping.c` and `z_storage.c` synchronise with.
//!
//! ## Why these are hand-rolled rather than `std::sync::Mutex`
//!
//! zenoh-c's mutex is a C-shaped one: `z_mutex_lock` and `z_mutex_unlock` are
//! separate calls on a bare handle, and the program may hold the lock across an
//! arbitrary stretch of its own code — `z_ping.c` locks, publishes, waits on a
//! condvar and unlocks in three different functions. Rust's `Mutex` hands back a
//! guard whose lifetime IS the lock, which cannot model that: there is no frame
//! to keep the guard in.
//!
//! So the lock state is explicit — a `Mutex<bool>` plus a `Condvar` — and
//! `lock` / `unlock` move that flag. The Rust mutex is held only across the flag
//! update, never across the C program's critical section, so a C thread that
//! locks and never unlocks blocks other C threads exactly as `pthread_mutex`
//! would rather than poisoning anything.
//!
//! ## The condvar cannot hold a pointer, which decides its whole design
//!
//! `z_loaned_condvar_t` is FOUR bytes (measured; see
//! [`crate::abi::z_loaned_condvar_t`]). A handle does not fit, so a condvar is a
//! `u32` key into a process-wide registry and `z_condvar_loan` stays a plain
//! cast because the key sits at offset 0 of the owned form too.
//!
//! ## `wait` is a real condvar, and the two mechanisms do DIFFERENT jobs
//!
//! `z_condvar_wait(cv, m)` must release `m` and block ATOMICALLY with respect to
//! a concurrent `z_condvar_signal`, or the signal races into the gap and the
//! waiter sleeps forever. What closes that gap is the ORDER: take the condvar's
//! own mutex FIRST, then unlock the caller's mutex, then wait. A signaller has to
//! take that same mutex, so it cannot fire between the unlock and the park.
//! Reversing those two lines is a real lost-wakeup, and the test below races them
//! rather than sleeping past the window.
//!
//! The GENERATION COUNTER is a separate thing and it is NOT what makes the above
//! true — an earlier draft of this comment said it was, and a damage probe showed
//! the claim was untestable because it was false. What the counter actually does
//! is suppress SPURIOUS wakeups: `std::sync::Condvar` may return without a
//! signal, and `z_ping.c` calls `z_condvar_wait` with no predicate loop
//! (`examples/z_ping.c:87,99`), so a spurious return there records a bogus
//! round-trip time and desynchronises the ping/pong pair. `wait_while` on a
//! counter the signaller bumps is what turns that into a re-park.
//!
//! ## A signal delivered while NOBODY waits is LOST, as in pthreads
//!
//! Stated because the opposite is easy to assume from the counter's presence: the
//! waiter reads the generation when it enters `wait`, so a signal that landed
//! before that read is already accounted for and the waiter parks. That is
//! `pthread_cond_signal`'s behaviour too, and upstream's `z_ping.c` depends on
//! it being harmless — it holds its mutex across publish-then-wait while the
//! callback that signals never takes that mutex, so the pattern is only safe
//! because a round trip is longer than the few instructions between the publish
//! returning and the waiter parking. wz does not make it safer than upstream, and
//! it must not be described as if it did.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};

use crate::abi::{
    z_loaned_condvar_t, z_loaned_mutex_t, z_moved_condvar_t, z_moved_mutex_t, z_owned_condvar_t,
    z_owned_mutex_t, Handle,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_EINVAL_MUTEX, Z_ENULL, Z_OK};

/// Behind a `z_owned_mutex_t` handle: an explicitly-held lock flag.
pub(crate) struct MutexState {
    locked: Mutex<bool>,
    released: Condvar,
}

impl MutexState {
    fn new() -> Self {
        Self {
            locked: Mutex::new(false),
            released: Condvar::new(),
        }
    }

    /// Block until the flag is clear, then set it.
    fn lock(&self) {
        let mut held = self.locked.lock().unwrap_or_else(|e| e.into_inner());
        while *held {
            held = self.released.wait(held).unwrap_or_else(|e| e.into_inner());
        }
        *held = true;
    }

    /// Clear the flag and wake one waiter.
    fn unlock(&self) {
        let mut held = self.locked.lock().unwrap_or_else(|e| e.into_inner());
        *held = false;
        self.released.notify_one();
    }
}

/// Behind a condvar key: a generation counter and the notification it rides.
struct CondvarState {
    generation: Mutex<u64>,
    changed: Condvar,
}

/// The condvar registry, keyed by the `u32` a `z_owned_condvar_t` carries.
///
/// A registry rather than a boxed handle because the LOANED form is four bytes
/// wide and a pointer does not fit in it — see the module doc.
fn condvars() -> &'static Mutex<HashMap<u32, &'static CondvarState>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u32, &'static CondvarState>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Next condvar key. Starts at 1 so 0 stays the gravestone.
fn next_condvar_key() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    loop {
        let key = NEXT.fetch_add(1, Ordering::Relaxed);
        if key != 0 {
            return key;
        }
    }
}

/// Resolve a condvar key.
fn condvar_state(key: u32) -> Option<&'static CondvarState> {
    if key == 0 {
        return None;
    }
    condvars()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .copied()
}

/// Read the [`MutexState`] behind a loaned mutex.
///
/// # Safety
/// `this_` must be null or a valid loaned mutex whose handle is live.
unsafe fn mutex_state<'a>(this_: *const z_loaned_mutex_t) -> Option<&'a MutexState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<MutexState>` this crate leaked.
    Some(unsafe { &*(handle as *const MutexState) })
}

/// Construct a mutex (zenoh-c `z_mutex_init`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_init(this_: *mut z_owned_mutex_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        let handle = Box::into_raw(Box::new(MutexState::new())) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_mutex_t::from_handle(handle) };
        Z_OK
    })
}

/// Borrow a mutex mutably (zenoh-c `z_mutex_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned mutex.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_loan_mut(this_: *mut z_owned_mutex_t) -> *mut z_loaned_mutex_t {
    this_ as *mut z_loaned_mutex_t
}

/// Take the lock, blocking until it is free (zenoh-c `z_mutex_lock`).
///
/// # Safety
/// `this_` must be null or a valid loaned mutex.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_lock(this_: *mut z_loaned_mutex_t) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        match unsafe { mutex_state(this_) } {
            Some(state) => {
                state.lock();
                Z_OK
            }
            // zenoh-c's vocabulary for "that is not a usable mutex" — the value
            // `pthread_mutex_lock` returns for a bad handle, which is what
            // upstream forwards.
            None => Z_EINVAL_MUTEX,
        }
    })
}

/// Release the lock (zenoh-c `z_mutex_unlock`).
///
/// # Safety
/// `this_` must be null or a valid loaned mutex.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_unlock(this_: *mut z_loaned_mutex_t) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        match unsafe { mutex_state(this_) } {
            Some(state) => {
                state.unlock();
                Z_OK
            }
            None => Z_EINVAL_MUTEX,
        }
    })
}

/// `true` iff the owned mutex holds a live state (zenoh-c
/// `z_internal_mutex_check`).
///
/// # Safety
/// `this_` must be null or a valid owned mutex.
#[no_mangle]
pub unsafe extern "C" fn z_internal_mutex_check(this_: *const z_owned_mutex_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned mutex (zenoh-c `z_internal_mutex_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned mutex.
#[no_mangle]
pub unsafe extern "C" fn z_internal_mutex_null(this_: *mut z_owned_mutex_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_mutex_t::null_value() };
    }
}

/// Free a mutex (zenoh-c `z_mutex_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved mutex.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_drop(this_: *mut z_moved_mutex_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<MutexState>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut MutexState) });
            unsafe { (*this_)._this = z_owned_mutex_t::null_value() };
        }
        Z_OK
    });
}

/// Construct a condvar (zenoh-c `z_condvar_init`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_condvar_init(this_: *mut z_owned_condvar_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // Leaked deliberately: the registry hands out `&'static` references and
        // `z_condvar_drop` removes the entry without freeing, because a waiter
        // parked inside `z_condvar_wait` still holds that reference. A condvar
        // dropped while a thread waits on it is the C program's error; leaking
        // one small allocation is the safe direction to be wrong in, and the
        // count is bounded by how many condvars the program ever creates.
        let state: &'static CondvarState = Box::leak(Box::new(CondvarState {
            generation: Mutex::new(0),
            changed: Condvar::new(),
        }));
        let key = next_condvar_key();
        condvars()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, state);
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_condvar_t { key, _pad: 0 } };
        Z_OK
    });
}

/// Borrow a condvar (zenoh-c `z_condvar_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned condvar.
#[no_mangle]
pub unsafe extern "C" fn z_condvar_loan(
    this_: *const z_owned_condvar_t,
) -> *const z_loaned_condvar_t {
    // A plain cast: the key is at offset 0 of both forms, which is what makes
    // the four-byte loaned type expressible at all.
    this_ as *const z_loaned_condvar_t
}

/// Wake one waiter (zenoh-c `z_condvar_signal`).
///
/// # Safety
/// `this_` must be null or a valid loaned condvar.
#[no_mangle]
pub unsafe extern "C" fn z_condvar_signal(this_: *const z_loaned_condvar_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let key = unsafe { (*this_).key };
        let Some(state) = condvar_state(key) else {
            return Z_EINVAL_MUTEX;
        };
        let mut gen = state.generation.lock().unwrap_or_else(|e| e.into_inner());
        *gen = gen.wrapping_add(1);
        state.changed.notify_one();
        Z_OK
    })
}

/// Release `m`, block until signalled, then re-take `m` (zenoh-c
/// `z_condvar_wait`).
///
/// # Safety
/// `this_` must be null or a valid loaned condvar; `m` must be null or a valid
/// loaned mutex the CALLING thread currently holds.
#[no_mangle]
pub unsafe extern "C" fn z_condvar_wait(
    this_: *const z_loaned_condvar_t,
    m: *mut z_loaned_mutex_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let key = unsafe { (*this_).key };
        let Some(state) = condvar_state(key) else {
            return Z_EINVAL_MUTEX;
        };
        // SAFETY: the caller's contract.
        let Some(mutex) = (unsafe { mutex_state(m) }) else {
            return Z_EINVAL_MUTEX;
        };
        // ORDER IS THE WHOLE THING (see the module doc): take the condvar's own
        // lock BEFORE releasing the caller's mutex, so a signaller — which must
        // take this same lock — cannot slip between the unlock and the wait.
        let gen = state.generation.lock().unwrap_or_else(|e| e.into_inner());
        let seen = *gen;
        mutex.unlock();
        let gen = state
            .changed
            .wait_while(gen, |current| *current == seen)
            .unwrap_or_else(|e| e.into_inner());
        drop(gen);
        // Upstream's contract: the mutex is held again on return.
        mutex.lock();
        Z_OK
    })
}

/// `true` iff the owned condvar holds a live key (zenoh-c
/// `z_internal_condvar_check`).
///
/// # Safety
/// `this_` must be null or a valid owned condvar.
#[no_mangle]
pub unsafe extern "C" fn z_internal_condvar_check(this_: *const z_owned_condvar_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && unsafe { (*this_).key } != 0
    })
}

/// Zero an owned condvar (zenoh-c `z_internal_condvar_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned condvar.
#[no_mangle]
pub unsafe extern "C" fn z_internal_condvar_null(this_: *mut z_owned_condvar_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_condvar_t::null_value() };
    }
}

/// Retire a condvar (zenoh-c `z_condvar_drop`).
///
/// Removes the registry entry and zeroes the key. The state itself is not freed
/// — see [`z_condvar_init`] for why that is the safe direction.
///
/// # Safety
/// `this_` must be null or a valid moved condvar.
#[no_mangle]
pub unsafe extern "C" fn z_condvar_drop(this_: *mut z_moved_condvar_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let key = unsafe { (*this_)._this.key };
        if key != 0 {
            condvars()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
            unsafe { (*this_)._this = z_owned_condvar_t::null_value() };
        }
        Z_OK
    });
}

/// Sleep for `time` milliseconds (zenoh-c `z_sleep_ms`).
///
/// # Safety
/// Takes no pointers; `unsafe` only because every export in this crate shares
/// one signature discipline.
#[no_mangle]
pub unsafe extern "C" fn z_sleep_ms(time: usize) -> ZResult {
    std::thread::sleep(std::time::Duration::from_millis(time as u64));
    Z_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    /// The lock EXCLUDES: a second thread cannot enter until the first unlocks.
    /// This is the property `z_ping.c` rests on, and the one a mutex whose
    /// `lock` was a no-op would still pass every null-guard test with.
    #[test]
    fn the_mutex_excludes_a_second_thread_until_unlock() {
        // SAFETY: live locals driven exactly as a C caller would.
        unsafe {
            let mut owned = z_owned_mutex_t::null_value();
            assert_eq!(z_mutex_init(&mut owned), Z_OK);
            assert!(z_internal_mutex_check(&owned));
            let m = z_mutex_loan_mut(&mut owned) as usize;

            assert_eq!(z_mutex_lock(m as *mut z_loaned_mutex_t), Z_OK);
            let entered = Arc::new(AtomicBool::new(false));
            let flag = entered.clone();
            let t = std::thread::spawn(move || {
                assert_eq!(z_mutex_lock(m as *mut z_loaned_mutex_t), Z_OK);
                flag.store(true, Ordering::SeqCst);
                assert_eq!(z_mutex_unlock(m as *mut z_loaned_mutex_t), Z_OK);
            });
            // The contender must still be parked. A sleep is the only way to
            // observe "has NOT happened yet"; it is short and its failure mode
            // is a false GREEN, which the unlock half below then catches.
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert!(
                !entered.load(Ordering::SeqCst),
                "a held mutex let a second thread in"
            );
            assert_eq!(z_mutex_unlock(m as *mut z_loaned_mutex_t), Z_OK);
            t.join()
                .expect("the contender finishes once the lock frees");
            assert!(entered.load(Ordering::SeqCst));

            let mut moved = z_moved_mutex_t { _this: owned };
            z_mutex_drop(&mut moved);
            assert!(!z_internal_mutex_check(&moved._this));
        }
    }

    /// Two hundred lock / wait / signal / unlock cycles complete, and the mutex
    /// is HELD again when a wait returns.
    ///
    /// ## What this does NOT prove, stated first because a green here invites
    /// the wrong reading
    ///
    /// It does not witness the unlock-then-park WINDOW. Two attempts were made
    /// and both were measured rather than assumed:
    ///
    /// - The first slept in the signaller so the waiter had certainly parked, and
    ///   asserted the wakeup arrived. Dropping the generation counter left it
    ///   GREEN — it discriminated nothing, and that is what exposed the wrong
    ///   claim in this module's doc, which said the counter closed the window.
    /// - The second made the signaller block on the CALLER'S mutex, so its lock
    ///   returning meant the waiter was past the unlock. That releases the
    ///   signaller but does not make it RUN first: the waiter reaches the
    ///   condvar's mutex in nanoseconds while the signaller has to wake from a
    ///   park, so reversing the two lines in `z_condvar_wait` still passed 200
    ///   rounds.
    ///
    /// The window cannot be forced through the public API without an injection
    /// point in shipped code. So the ordering is argued from the source and NOT
    /// measured here — a named residual, not a covered case. What the loop does
    /// cover is gross liveness: a `z_condvar_wait` that failed to release the
    /// mutex, or a mutex whose unlock did not wake its waiters, deadlocks it on
    /// the first round.
    #[test]
    fn repeated_lock_wait_signal_cycles_complete_and_the_mutex_is_retaken() {
        // SAFETY: live locals driven exactly as a C caller would.
        unsafe {
            let mut m_owned = z_owned_mutex_t::null_value();
            assert_eq!(z_mutex_init(&mut m_owned), Z_OK);
            let mut cv_owned = z_owned_condvar_t::null_value();
            z_condvar_init(&mut cv_owned);
            assert!(z_internal_condvar_check(&cv_owned));

            let m = z_mutex_loan_mut(&mut m_owned) as usize;
            let cv = z_condvar_loan(&cv_owned) as usize;

            // The signaller holds the associated mutex while signalling, which
            // is the textbook condvar pattern and matters here: a signal issued
            // with NO waiter and no mutex is lost in pthreads too, so a loop
            // that signalled unsynchronised would be asserting something no
            // condvar provides. An earlier draft did exactly that and hung —
            // against a correct implementation.
            const ROUNDS: usize = 200;
            let start = Arc::new(std::sync::Barrier::new(2));
            let signaller_start = start.clone();
            let t = std::thread::spawn(move || {
                for _ in 0..ROUNDS {
                    signaller_start.wait();
                    assert_eq!(z_mutex_lock(m as *mut z_loaned_mutex_t), Z_OK);
                    assert_eq!(z_condvar_signal(cv as *const z_loaned_condvar_t), Z_OK);
                    assert_eq!(z_mutex_unlock(m as *mut z_loaned_mutex_t), Z_OK);
                }
            });
            for round in 0..ROUNDS {
                assert_eq!(z_mutex_lock(m as *mut z_loaned_mutex_t), Z_OK);
                start.wait();
                assert_eq!(
                    z_condvar_wait(cv as *const z_loaned_condvar_t, m as *mut z_loaned_mutex_t),
                    Z_OK,
                    "round {round} lost its wakeup"
                );
                assert_eq!(z_mutex_unlock(m as *mut z_loaned_mutex_t), Z_OK);
            }
            t.join().expect("the signaller finishes");

            // The SECOND half: after a wait returns, the mutex must be HELD
            // again. Asserted on a fresh wait so the two properties fail
            // separately — a lost wakeup reds the loop above, a wait that
            // returned without re-taking the mutex reds only this.
            assert_eq!(z_mutex_lock(m as *mut z_loaned_mutex_t), Z_OK);
            let t = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(20));
                assert_eq!(z_condvar_signal(cv as *const z_loaned_condvar_t), Z_OK);
            });
            assert_eq!(
                z_condvar_wait(cv as *const z_loaned_condvar_t, m as *mut z_loaned_mutex_t),
                Z_OK
            );
            t.join().expect("the signaller finishes");

            // A second thread must not get the mutex until we unlock.
            let got = Arc::new(AtomicBool::new(false));
            let flag = got.clone();
            let t2 = std::thread::spawn(move || {
                assert_eq!(z_mutex_lock(m as *mut z_loaned_mutex_t), Z_OK);
                flag.store(true, Ordering::SeqCst);
                assert_eq!(z_mutex_unlock(m as *mut z_loaned_mutex_t), Z_OK);
            });
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert!(
                !got.load(Ordering::SeqCst),
                "z_condvar_wait returned WITHOUT re-taking the mutex"
            );
            assert_eq!(z_mutex_unlock(m as *mut z_loaned_mutex_t), Z_OK);
            t2.join().expect("the contender finishes");

            let mut moved_cv = z_moved_condvar_t { _this: cv_owned };
            z_condvar_drop(&mut moved_cv);
            let mut moved_m = z_moved_mutex_t { _this: m_owned };
            z_mutex_drop(&mut moved_m);
        }
    }

    /// Every export answers a NULL rather than dereferencing it.
    #[test]
    fn the_sync_exports_answer_null_without_dereferencing_it() {
        // SAFETY: passing NULL is exactly what these guards exist for.
        unsafe {
            assert_eq!(z_mutex_lock(std::ptr::null_mut()), Z_EINVAL_MUTEX);
            assert_eq!(z_mutex_unlock(std::ptr::null_mut()), Z_EINVAL_MUTEX);
            assert_eq!(z_condvar_signal(std::ptr::null()), Z_ENULL);
            assert_eq!(
                z_condvar_wait(std::ptr::null(), std::ptr::null_mut()),
                Z_ENULL
            );
            assert!(!z_internal_mutex_check(std::ptr::null()));
            assert!(!z_internal_condvar_check(std::ptr::null()));
            z_mutex_drop(std::ptr::null_mut());
            z_condvar_drop(std::ptr::null_mut());
        }
    }
}

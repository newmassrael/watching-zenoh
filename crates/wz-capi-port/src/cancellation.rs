// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The ONE cancellation token both C ABIs hand out, and the fan a get registers on it.
//!
//! ## Why it lives here
//!
//! Both upstreams cancel in the same shape, which is what makes one model the right answer rather
//! than a convenience:
//!
//! * zenoh (the Rust the zenoh-c ABI wraps): `cancel` takes the handler set,
//!   runs it, then waits on a sync group every registered query holds a
//!   notifier of until that query's callback is dropped
//!   (`zenoh/src/api/cancellation.rs` @ `Ok(_) => self.sync_group.wait(),`);
//!   a query registers its handler and notifier, and the callback's drop
//!   releases both
//!   (`zenoh/src/api/session.rs` @ `ct.remove_on_cancel_handler(handler_id);`).
//! * zenoh-pico: `_z_cancellation_token_cancel` runs the handlers, then
//!   `_z_sync_group_wait`s
//!   (`vendor/zenoh-pico/src/session/cancellation.c` @ `_z_sync_group_wait(&ct->_sync_group);`).
//!
//! It is the port's and not an engine's: an ABI hands the token out, and the engine that issues
//! a get is told which fan each leg belongs to, whichever engine that is.
//!
//! ## The contract
//!
//! * A get's registration IS its [`CancellableFan`]: [`CancellableFan::register`] links the fan
//!   into its token's list, so registering takes no memory, and the fan lies wherever the get
//!   keeps it (a place of the session's, or a value of the caller's). Registering is refused once
//!   a cancel has STARTED, so a query issued with an already-cancelled token fails instead of
//!   running uncancellably (upstream's "Query was cancelled" / `Z_ERR_CANCELLED`).
//! * The fan is dropped when the get is over by any route (completed, timed out, its face lost,
//!   cancelled), after its callbacks: its drop unlinks it and leaves the token's sync group.
//! * [`CancellationToken::cancel`] takes each linked fan off the list under the token's lock and
//!   cancels it with no lock held (the engine's cancel drops a pending leg, whose callback's drop
//!   runs the C `drop(context)`, and a C callback may re-enter the session), then blocks until
//!   every registered fan has been dropped. A concurrent second `cancel` waits for the first's
//!   cancels as well as the fans.
//! * A fan cancels its legs through ONE engine canceller ([`FanCanceller`]), which the engine
//!   attaches as it issues the legs ([`CancellableFan::attach`]) and which ends every pending
//!   leg the engine tagged with the fan's key ([`CancellableFan::key`]): no leg carries an undo
//!   of its own. A fan cancelled before the engine attached refuses the attachment, and the
//!   engine then ends what it issued itself and issues nothing further.
//! * [`CancellationToken::is_cancelled`] is true once the fans have been cancelled, which is
//!   upstream zenoh's `cancel_result.get().is_some()`.
//!
//! ## What a cancelled query's CALLER must not do
//!
//! Call `cancel` from inside the very callback it would wait for: the wait
//! cannot finish while that callback is running. Upstream has the same
//! property (its wait is on the same notifier), and it is named here rather
//! than guarded because a guard would need to know which thread is inside
//! which callback.
//!
//! ## Where it builds
//!
//! Wherever the port does. The token BLOCKS: its cancel waits until every
//! registration is dropped, on the port's condition variable ([`crate::os`]):
//! `std`'s on a host, the host's own calls' in a host library without `std`,
//! an MCU kernel's in an image. The fan only takes a lock ([`crate::sync::Lock`]).

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ptr::NonNull;

use crate::os::{Condvar, Mutex, MutexGuard};
use crate::sync::Lock;

/// A one-shot undo of one leg, which an engine that keeps no key on its pending legs records.
type OnCancel = Box<dyn FnOnce() + Send>;

/// The token's state, under one lock so "cancel has started", "the fans are off the list" and
/// "no registration can land" are one fact rather than three.
struct Inner {
    /// The first registered fan not yet cancelled; each links the next.
    head: Option<NonNull<CancellableFan>>,
    /// A cancel has started: no fan registers from now on.
    started: bool,
    /// Fans registered and not yet dropped, plus one while a cancel is RUNNING its fans'
    /// cancels (upstream's `execution_finished_notifier`), so a concurrent cancel cannot return
    /// before those have finished.
    active: usize,
    /// The fans have been cancelled.
    cancelled: bool,
}

// SAFETY: the fans `head` reaches are `Sync`, and the list is read and changed only under the
// token's lock.
unsafe impl Send for Inner {}

/// A cancellation token shared by every handle a C program holds on it, or lying in the place of
/// what owns it (a querier's).
pub struct CancellationToken {
    inner: Mutex<Inner>,
    idle: Condvar,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                head: None,
                started: false,
                active: 0,
                cancelled: false,
            }),
            idle: Condvar::new(),
        }
    }
}

impl CancellationToken {
    /// A fresh, uncancelled token, shared.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Lock. The port's lock treats a poisoned one as usable: every critical
    /// section here leaves `Inner` consistent before it can panic.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock()
    }

    /// Whether the fans have been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.lock().cancelled
    }

    /// Cancel: cancel every registered fan, then wait until every registered fan has been
    /// dropped.
    pub fn cancel(&self) {
        let runs = {
            let mut inner = self.lock();
            let runs = !inner.started;
            if runs {
                inner.started = true;
                // This call cancels the fans; hold the group open meanwhile.
                inner.active = inner.active.saturating_add(1);
            }
            runs
        };
        if runs {
            // One fan at a time, taken off the list under the lock and cancelled after it: once
            // off the list the fan is not touched again here, since its cancel may end its get
            // and give back the place it lies in.
            while let Some(taken) = self.take_first() {
                taken.run();
            }
            let mut inner = self.lock();
            inner.cancelled = true;
            // The count this call took above.
            inner.active = inner.active.saturating_sub(1);
            if inner.active == 0 {
                self.idle.notify_all();
            }
        }
        let mut inner = self.lock();
        while inner.active > 0 {
            inner = self.idle.wait(inner);
        }
    }

    /// Take the first registered fan off the list and mark it cancelled, answering what cancels
    /// its legs; `None` once the list is empty.
    fn take_first(&self) -> Option<Cancelling> {
        let mut inner = self.lock();
        let node = inner.head?;
        // SAFETY: a linked fan stands until its drop unlinks it, which takes this lock.
        let fan = unsafe { node.as_ref() };
        // SAFETY: a fan's link is read and written only under its token's lock, held here.
        let link = unsafe { &mut *fan.link.get() };
        inner.head = link.next.take();
        link.linked = false;
        Some(fan.mark_cancelled().unwrap_or_default())
    }

    /// Fans registered and not yet dropped, plus a running cancel. For tests and diagnostics.
    pub fn active(&self) -> usize {
        self.lock().active
    }
}

/// The token a fan is registered on: one its handles share, or one lying in its owner's place.
pub struct TokenRef(Held);

enum Held {
    Shared(Arc<CancellationToken>),
    Placed(NonNull<CancellationToken>),
}

impl TokenRef {
    /// A token the program's handles share; the fan holds one more of them.
    pub fn shared(token: Arc<CancellationToken>) -> Self {
        Self(Held::Shared(token))
    }

    /// A token lying in its owner's place, as a querier's does.
    ///
    /// # Safety
    /// `token` does not move, and is not dropped until every fan registered on it has been
    /// dropped: its owner cancels it, which waits for them, before letting it go.
    pub unsafe fn placed(token: &CancellationToken) -> Self {
        Self(Held::Placed(NonNull::from(token)))
    }

    fn get(&self) -> &CancellationToken {
        match &self.0 {
            Held::Shared(token) => token,
            // SAFETY: `placed`'s caller keeps the token standing while a fan holds it.
            Held::Placed(token) => unsafe { token.as_ref() },
        }
    }
}

/// Which fan a pending leg belongs to: the fan's address, which does not change while the fan
/// stands, and the serial it was named under. A fan's place is given back with its get's last
/// leg and may hold the next get's fan, so a cancel still running for the first must not name the
/// second: the serial tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FanKey(usize, u64);

/// The serials fans are named under, one each, the first time an engine asks a fan's key.
static SERIALS: Lock<u64> = Lock::new(0);

/// The engine end of a fan's cancellation: the engine that issued the legs ends them.
pub trait FanCanceller: Send + Sync {
    /// End every leg tagged `key` that is still pending. Called with no lock of the fan's or its
    /// token's held, and possibly more than once for one fan.
    fn cancel_fan(&self, key: FanKey);

    /// The fan `key` is dropped without having been cancelled: forget whatever is kept for it.
    /// An engine whose pending legs end before their fan does keeps nothing past them, which is
    /// the provided answer.
    fn fan_over(&self, key: FanKey) {
        let _ = key;
    }
}

/// What cancels a fan's legs, taken from it as it is cancelled.
#[derive(Default)]
struct Cancelling {
    key: Option<FanKey>,
    canceller: Option<Weak<dyn FanCanceller>>,
    undo: Vec<OnCancel>,
}

impl Cancelling {
    fn run(self) {
        if let (Some(key), Some(canceller)) = (self.key, self.canceller.and_then(|c| c.upgrade())) {
            canceller.cancel_fan(key);
        }
        for undo in self.undo {
            undo();
        }
    }
}

/// The fan's own state, under its lock.
struct FanState {
    /// Cancelled: by its token, or by its owner. Nothing further is issued.
    cancelled: bool,
    /// The engine that ends the legs tagged with the fan's key.
    canceller: Option<Weak<dyn FanCanceller>>,
    /// The legs an engine that keeps no key on them recorded one undo for.
    undo: Vec<OnCancel>,
    /// The serial of the fan's key; `0` until the key is first asked.
    serial: u64,
}

impl FanState {
    /// The key of the fan at `at`, named now if it was not yet.
    fn key_at(&mut self, at: usize) -> FanKey {
        if self.serial == 0 {
            self.serial = SERIALS.with(|next| {
                *next = next.wrapping_add(1).max(1);
                *next
            });
        }
        FanKey(at, self.serial)
    }
}

/// A fan's place in its token's list, read and written under the token's lock.
struct Link {
    next: Option<NonNull<CancellableFan>>,
    linked: bool,
}

/// The legs one get issued across a fan of faces, as one thing to cancel, and the get's
/// registration on its token.
///
/// A fan issues ONE query per face, each with its own id, so cancellation is a set operation;
/// the engine tags each pending leg with the fan's key and cancels the set through the one
/// canceller it attaches. The fan is registered BEFORE the first face is issued (upstream's
/// ordering), so a token cancelled mid-fan must be able to stop the loop: a cancelled fan refuses
/// the engine's attachment, and the engine issues nothing further.
pub struct CancellableFan {
    state: Lock<FanState>,
    /// The token this fan is registered on; written once by its owner before the fan is handed
    /// to an engine, and read in its drop.
    token: UnsafeCell<Option<TokenRef>>,
    link: UnsafeCell<Link>,
}

// SAFETY: `state` is behind its lock; `link` is read and written only under the token's lock;
// `token` is written by `register`, whose caller has the fan to itself, and read by the drop.
unsafe impl Send for CancellableFan {}
// SAFETY: as `Send`'s.
unsafe impl Sync for CancellableFan {}

impl Default for CancellableFan {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellableFan {
    /// An empty, uncancelled fan, registered on no token.
    pub const fn new() -> Self {
        Self {
            state: Lock::new(FanState {
                cancelled: false,
                canceller: None,
                undo: Vec::new(),
                serial: 0,
            }),
            token: UnsafeCell::new(None),
            link: UnsafeCell::new(Link {
                next: None,
                linked: false,
            }),
        }
    }

    /// The key the engine tags this fan's pending legs with.
    pub fn key(&self) -> FanKey {
        let at = self.address();
        self.state.with(|state| state.key_at(at))
    }

    fn address(&self) -> usize {
        core::ptr::from_ref(self) as usize
    }

    /// Register the fan on `token`, before any leg is issued. `false` when the token has
    /// already started cancelling: the caller then fails the get without issuing it.
    ///
    /// # Safety
    /// Called once, by the fan's owner before it hands the fan to an engine; the fan does not
    /// move from here until it is dropped.
    pub unsafe fn register(&self, token: TokenRef) -> bool {
        let slot = self.token.get();
        // SAFETY: the caller's: nothing else reaches the token slot yet.
        let token = unsafe { (*slot).insert(token) }.get();
        let linked = {
            let mut inner = token.lock();
            if inner.started {
                false
            } else {
                // SAFETY: the link is written under the token's lock, held here.
                unsafe {
                    *self.link.get() = Link {
                        next: inner.head,
                        linked: true,
                    };
                }
                inner.head = Some(NonNull::from(self));
                inner.active = inner.active.saturating_add(1);
                true
            }
        };
        if !linked {
            // Let go of the token after its lock: this may be its last handle.
            // SAFETY: as above.
            drop(unsafe { (*slot).take() });
        }
        linked
    }

    /// Attach the engine that ends this fan's legs, as it issues one. `false` when the fan has
    /// already been cancelled: the engine then ends what it tagged with [`Self::key`] itself
    /// and issues nothing further. A fan's legs are issued by one engine, so a second attachment
    /// keeps the first.
    pub fn attach(&self, canceller: &Weak<dyn FanCanceller>) -> bool {
        self.state.with(|state| {
            if state.cancelled {
                return false;
            }
            if state.canceller.is_none() {
                state.canceller = Some(Weak::clone(canceller));
            }
            true
        })
    }

    /// Record one leg's undo, for an engine that keeps no key on its pending legs, or report that
    /// the fan was cancelled while it was being issued, in which case `undo` runs HERE, since
    /// the cancel that already ran could not have seen it.
    pub fn record(&self, undo: impl FnOnce() + Send + 'static) -> bool {
        let undo: OnCancel = Box::new(undo);
        let refused = self.state.with(|state| {
            if state.cancelled {
                Some(undo)
            } else {
                state.undo.push(undo);
                None
            }
        });
        match refused {
            None => true,
            Some(undo) => {
                undo();
                false
            }
        }
    }

    /// Whether the fan has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.state.with(|state| state.cancelled)
    }

    /// Cancel the fan: every leg issued so far is ended, and none further is issued.
    pub fn cancel(&self) {
        if let Some(cancelling) = self.mark_cancelled() {
            cancelling.run();
        }
    }

    /// Mark the fan cancelled and take what ends its legs, to run with no lock held; `None`
    /// when it was cancelled already.
    fn mark_cancelled(&self) -> Option<Cancelling> {
        let at = self.address();
        self.state.with(|state| {
            if state.cancelled {
                return None;
            }
            state.cancelled = true;
            Some(Cancelling {
                key: Some(state.key_at(at)),
                canceller: state.canceller.take(),
                undo: core::mem::take(&mut state.undo),
            })
        })
    }
}

impl Drop for CancellableFan {
    fn drop(&mut self) {
        let at = self.address();
        // Not cancelled: its engine is told it is over, and its undos are forgotten with it.
        let (canceller, key) = self
            .state
            .with(|state| (state.canceller.take(), state.key_at(at)));
        if let Some(canceller) = canceller.and_then(|c| c.upgrade()) {
            canceller.fan_over(key);
        }
        let Some(token) = self.token.get_mut().take() else {
            return;
        };
        let me: *const Self = self;
        {
            let mut inner = token.get().lock();
            let link = self.link.get();
            // SAFETY: the links are read and written under the token's lock, held here, and a
            // linked fan stands until its own drop unlinks it.
            unsafe {
                if (*link).linked {
                    let mut at: *mut Option<NonNull<Self>> = &mut inner.head;
                    while let Some(node) = *at {
                        if core::ptr::eq(node.as_ptr(), me) {
                            *at = (*link).next.take();
                            break;
                        }
                        at = &mut (*node.as_ref().link.get()).next;
                    }
                    (*link).linked = false;
                }
            }
            // The count `register` took for this fan.
            inner.active = inner.active.saturating_sub(1);
            if inner.active == 0 {
                token.get().idle.notify_all();
            }
        }
        // Let go of the token after its lock: this may be its last handle.
        drop(token);
    }
}

/// A fan of its own allocation registered on `token`, for a caller that shares the fan among the
/// legs it issues. `None` when the token has already started cancelling: the caller then fails
/// the get without issuing it.
pub fn register_fan(token: &Arc<CancellationToken>) -> Option<Arc<CancellableFan>> {
    let fan = Arc::new(CancellableFan::new());
    // SAFETY: the fan is its allocation's own, which does not move until it is dropped, and no
    // engine has it yet.
    unsafe { fan.register(TokenRef::shared(Arc::clone(token))) }.then_some(fan)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    // The tests' own shared state is std's; the token's lock is the port's.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    /// An engine that writes down what it was asked to do, by fan.
    #[derive(Default)]
    struct Seen(Mutex<Vec<(FanKey, &'static str)>>);

    impl FanCanceller for Seen {
        fn cancel_fan(&self, key: FanKey) {
            self.0.lock().unwrap().push((key, "cancel"));
        }
        fn fan_over(&self, key: FanKey) {
            self.0.lock().unwrap().push((key, "over"));
        }
    }

    impl Seen {
        fn taken(&self) -> Vec<(FanKey, &'static str)> {
            self.0.lock().unwrap().clone()
        }
    }

    fn canceller_of(engine: &Arc<Seen>) -> Weak<dyn FanCanceller> {
        Arc::downgrade(engine)
    }

    /// A registered fan is cancelled through the engine attached to it, by its key, and the
    /// token's `cancel` does not return until the fan is dropped; a cancelled token refuses the
    /// next registration. Turned red by a cancel that returns before the fan's drop, or that
    /// does not reach the fan's engine.
    #[test]
    fn a_registered_fan_is_cancelled_through_its_engine_and_waited_for() {
        let token = CancellationToken::new();
        let engine = Arc::new(Seen::default());
        let fan = register_fan(&token).expect("a fresh token registers");
        assert!(fan.attach(&canceller_of(&engine)));
        assert_eq!(token.active(), 1);
        let key = fan.key();
        let order = Mutex::new(Vec::new());
        std::thread::scope(|s| {
            s.spawn(|| {
                token.cancel();
                order.lock().unwrap().push("cancel returned");
            });
            while engine.taken().is_empty() {
                std::thread::sleep(Duration::from_millis(1));
            }
            std::thread::sleep(Duration::from_millis(50));
            order.lock().unwrap().push("fan dropped");
            drop(fan);
        });
        assert_eq!(
            *order.lock().unwrap(),
            vec!["fan dropped", "cancel returned"]
        );
        assert_eq!(engine.taken(), vec![(key, "cancel")]);
        assert!(token.is_cancelled());
        assert_eq!(token.active(), 0);
        assert!(register_fan(&token).is_none(), "cancel has started");
    }

    /// A fan cancelled before its engine attached refuses the attachment, and a fan dropped
    /// uncancelled tells its engine it is over. Turned red by an attachment a cancelled fan
    /// accepts, which would issue legs nothing cancels.
    #[test]
    fn a_cancelled_fan_refuses_its_engine_and_an_uncancelled_one_says_it_is_over() {
        let engine = Arc::new(Seen::default());
        let canceller = canceller_of(&engine);
        let fan = CancellableFan::new();
        fan.cancel();
        assert!(fan.is_cancelled());
        assert!(!fan.attach(&canceller));
        drop(fan);
        assert!(engine.taken().is_empty(), "no engine was attached");

        let fan = CancellableFan::new();
        assert!(fan.attach(&canceller));
        let key = fan.key();
        drop(fan);
        assert_eq!(engine.taken(), vec![(key, "over")]);
    }

    /// Fans lying in places of their own, on a token lying in its owner's: one dropped from the
    /// middle of the list is unlinked, and the cancel reaches exactly the others. Turned red by
    /// an unlink that leaves the dropped fan on the list.
    #[test]
    fn a_fan_dropped_from_the_middle_is_off_its_tokens_list() {
        let token = CancellationToken::default();
        let engine = Arc::new(Seen::default());
        let canceller = canceller_of(&engine);
        let mut fans: Vec<Box<CancellableFan>> = (0..3).map(|_| Box::default()).collect();
        for fan in &fans {
            // SAFETY: each fan is its box's and is not moved; the token is dropped after them.
            assert!(unsafe { fan.register(TokenRef::placed(&token)) });
            assert!(fan.attach(&canceller));
        }
        assert_eq!(token.active(), 3);
        let keys: Vec<FanKey> = fans.iter().map(|fan| fan.key()).collect();
        drop(fans.remove(1));
        assert_eq!(token.active(), 2);
        assert_eq!(engine.taken(), vec![(keys[1], "over")]);
        std::thread::scope(|s| {
            s.spawn(|| token.cancel());
            while engine.taken().len() < 3 {
                std::thread::sleep(Duration::from_millis(1));
            }
            drop(fans);
        });
        assert_eq!(
            engine.taken(),
            vec![(keys[1], "over"), (keys[2], "cancel"), (keys[0], "cancel")]
        );
        assert_eq!(token.active(), 0);
    }

    /// An undo recorded before the cancel is run by it; one recorded after runs on the spot and
    /// reports `false`.
    #[test]
    fn a_recorded_undo_runs_once_whenever_the_fan_is_cancelled() {
        let undone = Arc::new(AtomicUsize::new(0));
        let fan = CancellableFan::new();
        let u = Arc::clone(&undone);
        assert!(fan.record(move || {
            u.fetch_add(1, Ordering::SeqCst);
        }));
        fan.cancel();
        fan.cancel();
        assert_eq!(undone.load(Ordering::SeqCst), 1);
        let u = Arc::clone(&undone);
        assert!(!fan.record(move || {
            u.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(
            undone.load(Ordering::SeqCst),
            2,
            "a late record undoes itself"
        );
    }
}

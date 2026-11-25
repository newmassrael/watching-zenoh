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

use core::cell::UnsafeCell;
use core::ptr::{addr_of_mut, NonNull};

#[cfg(any(
    all(test, feature = "std"),
    all(not(feature = "std"), not(feature = "os-sys"))
))]
use crate::lodge::StaticPlaces;
use crate::lodge::{Lent, NoPlace, Strong};
use crate::os::{Condvar, Mutex, MutexGuard};
use crate::sync::Lock;
use wz_session_core::caps;

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

impl CancellationToken {
    /// A fresh, uncancelled token, made in `place`, where it stays: its lock and its condition
    /// variable are made there ([`crate::os::mutex_in`]).
    ///
    /// # Safety
    /// `place` is valid for writes of a `Self` and aligned for it, and what it held is overwritten
    /// without being dropped. The token is not moved from `place` until it is dropped there.
    pub unsafe fn init_in(place: NonNull<Self>) {
        let at = place.as_ptr();
        // SAFETY: each field is a place inside `place`, so not null, and the caller's contract is
        // `mutex_in`'s and `condvar_in`'s for it; each is made once.
        unsafe {
            crate::os::mutex_in(NonNull::new_unchecked(addr_of_mut!((*at).inner)), |inner| {
                inner.write(Inner {
                    head: None,
                    started: false,
                    active: 0,
                    cancelled: false,
                })
            });
            crate::os::condvar_in(NonNull::new_unchecked(addr_of_mut!((*at).idle)));
        }
    }

    /// A fresh, uncancelled token, shared by counts: in a place of the process's table of tokens
    /// in a kernel's build, which asks nothing of a heap, and in a box of its own on a host;
    /// [`NoPlace`] when every place is held or the heap refuses the box.
    pub fn new() -> Result<Strong<Self>, NoPlace> {
        let make = |place: NonNull<Self>| {
            // SAFETY: the place is its lodging's, valid for one token, holding none, never moved.
            unsafe { Self::init_in(place) }
        };
        // SAFETY: `make` makes the whole token in the place it is handed.
        unsafe { lodge_token(make) }
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
    Shared(Strong<CancellationToken>),
    Placed(NonNull<CancellationToken>),
}

impl TokenRef {
    /// A token the program's handles share; the fan holds one more of them.
    pub fn shared(token: Strong<CancellationToken>) -> Self {
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

/// Which fan a pending leg belongs to: the fan's address where it was first named, and the serial
/// it was named under. A fan's place is given back with its get's last
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

/// What names a session's engine in the table of engines its own crate keeps, which keeps nothing
/// of the engine standing: a row and the generation the row was at when the engine was put in it.
/// The port only hands it back to that crate ([`Canceller::Engine`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineAt {
    /// The row of the table.
    pub row: usize,
    /// The generation of the row the engine was put in at.
    pub generation: u32,
}

/// What a fan tells the engine that ends its legs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FanEnd {
    /// The fan was cancelled: end its legs ([`FanCanceller::cancel_fan`]).
    Cancel(FanKey),
    /// The fan was dropped uncancelled ([`FanCanceller::fan_over`]).
    Over(FanKey),
}

impl FanEnd {
    /// Tell `canceller` this end.
    pub fn tell<C: FanCanceller + ?Sized>(self, canceller: &C) {
        match self {
            Self::Cancel(key) => canceller.cancel_fan(key),
            Self::Over(key) => canceller.fan_over(key),
        }
    }
}

/// The engine end a fan is attached to: one that stands for the whole process, or a session's
/// engine named in its crate's table ([`EngineAt`]), which keeps nothing of the engine standing
/// and reaches nothing once its session closed.
#[derive(Clone, Copy)]
pub enum Canceller {
    /// A canceller of the process's, which every engine of a kind shares.
    Static(&'static dyn FanCanceller),
    /// The engine `at` names, told a fan's end by `ends`, its crate's: under a count of the
    /// engine taken for the call while its session is open, and not at all once it closed.
    Engine {
        /// The engine, in its crate's table.
        at: EngineAt,
        /// What reaches the engine `at` names and tells it the end.
        ends: fn(EngineAt, FanEnd),
    },
}

impl Canceller {
    /// Tell the canceller `end`: at once for a static one, through its crate for an engine's.
    fn tell(self, end: FanEnd) {
        match self {
            Self::Static(canceller) => end.tell(canceller),
            Self::Engine { at, ends } => ends(at, end),
        }
    }
}

/// What cancels a fan's legs, taken from it as it is cancelled.
#[derive(Default)]
struct Cancelling {
    key: Option<FanKey>,
    canceller: Option<Canceller>,
}

impl Cancelling {
    fn run(self) {
        if let (Some(key), Some(canceller)) = (self.key, self.canceller) {
            canceller.tell(FanEnd::Cancel(key));
        }
    }
}

/// The fan's own state, under its lock.
struct FanState {
    /// Cancelled: by its token, or by its owner. Nothing further is issued.
    cancelled: bool,
    /// The engine that ends the legs tagged with the fan's key.
    canceller: Option<Canceller>,
    /// The fan's key, named where the fan lies the first time it is asked, so a fan moved after
    /// it was named is still told apart by the key its engine tagged its legs with.
    key: Option<FanKey>,
}

impl FanState {
    /// The key of the fan at `at`, named now if it was not yet.
    fn key_at(&mut self, at: usize) -> FanKey {
        *self.key.get_or_insert_with(|| {
            let serial = SERIALS.with(|next| {
                *next = next.wrapping_add(1).max(1);
                *next
            });
            FanKey(at, serial)
        })
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
                key: None,
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
    pub fn attach(&self, canceller: Canceller) -> bool {
        self.state.with(|state| {
            if state.cancelled {
                return false;
            }
            if state.canceller.is_none() {
                state.canceller = Some(canceller);
            }
            true
        })
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
            })
        })
    }
}

impl Drop for CancellableFan {
    fn drop(&mut self) {
        let at = self.address();
        // Not cancelled: its engine is told it is over.
        let (canceller, key) = self
            .state
            .with(|state| (state.canceller.take(), state.key_at(at)));
        if let Some(canceller) = canceller {
            canceller.tell(FanEnd::Over(key));
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

/// A fan in a box of its own registered on `token`, counted for a caller that shares the fan
/// among the legs it issues. `Ok(None)` when the token has already started cancelling: the caller
/// then fails the get without issuing it. [`NoPlace`] when the heap has no room for the fan.
pub fn register_fan(
    token: &Strong<CancellationToken>,
) -> Result<Option<Strong<CancellableFan>>, NoPlace> {
    let fan = Strong::new_at(Lent::try_boxed()?, CancellableFan::new());
    // SAFETY: the fan lies in its box, which does not move until its last count drops it, and no
    // engine has it yet.
    Ok(unsafe { fan.register(TokenRef::shared(token.clone())) }.then_some(fan))
}

/// How many tokens a kernel's build holds at once, read off the build's limits: a token is held to
/// cancel gets, and a process has at most this many gets pending at once, each of its engines'
/// rows ([`caps::ENGINE_ROWS`]) as many as its session's tables admit, queries and a querier's
/// queries in one ([`caps::MAX_PENDING_QUERIES`]) and liveliness gets in the other
/// ([`caps::MAX_PENDING_LIVELINESS_GETS`]). A program holding a token for each get it has pending
/// is never refused one; the next past them is, as a full heap refuses pico's. Moved as those
/// limits are, by the build's configuration.
pub const TOKEN_PLACES: usize = caps::ENGINE_ROWS
    .saturating_mul(caps::MAX_PENDING_QUERIES.saturating_add(caps::MAX_PENDING_LIVELINESS_GETS));

/// The process's places for tokens in a kernel's build.
#[cfg(all(not(feature = "std"), not(feature = "os-sys")))]
static TOKENS: StaticPlaces<CancellationToken, TOKEN_PLACES> = StaticPlaces::new();

/// The token `make` writes, in a place of [`TOKENS`], or [`NoPlace`] when every one is held.
///
/// # Safety
/// `make` leaves a whole token in the place it is handed, which is valid for writes of one.
#[cfg(all(not(feature = "std"), not(feature = "os-sys")))]
unsafe fn lodge_token(
    make: impl FnOnce(NonNull<CancellationToken>),
) -> Result<Strong<CancellationToken>, NoPlace> {
    // SAFETY: the caller's.
    unsafe { lodge_in_table(&TOKENS, make) }
}

/// The token `make` writes, in a place of `table`, or [`NoPlace`] when every one is held.
///
/// # Safety
/// As [`lodge_token`].
#[cfg(any(
    all(test, feature = "std"),
    all(not(feature = "std"), not(feature = "os-sys"))
))]
unsafe fn lodge_in_table<const N: usize>(
    table: &'static StaticPlaces<CancellationToken, N>,
    make: impl FnOnce(NonNull<CancellationToken>),
) -> Result<Strong<CancellationToken>, NoPlace> {
    let lent = table.lend().ok_or(NoPlace)?;
    // SAFETY: the caller's.
    Ok(unsafe { Strong::lodge_at(lent, make) })
}

/// The token `make` writes, in a box of its own, or [`NoPlace`] when the heap refuses it.
///
/// # Safety
/// As the kernel's form.
#[cfg(any(feature = "std", feature = "os-sys"))]
unsafe fn lodge_token(
    make: impl FnOnce(NonNull<CancellationToken>),
) -> Result<Strong<CancellationToken>, NoPlace> {
    // SAFETY: the caller's.
    unsafe { Strong::try_boxed_in(make) }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    // The tests' own shared state is std's; the token's lock is the port's.
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

    /// A stand-in engine for the whole test process, as a static canceller is: each test's own.
    fn engine() -> &'static Seen {
        Box::leak(Box::default())
    }

    fn canceller_of(engine: &'static Seen) -> Canceller {
        Canceller::Static(engine)
    }

    /// A registered fan is cancelled through the engine attached to it, by its key, and the
    /// token's `cancel` does not return until the fan is dropped; a cancelled token refuses the
    /// next registration. Turned red by a cancel that returns before the fan's drop, or that
    /// does not reach the fan's engine.
    #[test]
    fn a_registered_fan_is_cancelled_through_its_engine_and_waited_for() {
        let token = CancellationToken::new().expect("a token place is free");
        let engine = engine();
        let fan = register_fan(&token)
            .expect("the test's heap")
            .expect("a fresh token registers");
        assert!(fan.attach(canceller_of(engine)));
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
        assert!(
            register_fan(&token).expect("the test's heap").is_none(),
            "cancel has started"
        );
    }

    /// A fan cancelled before its engine attached refuses the attachment, and a fan dropped
    /// uncancelled tells its engine it is over. Turned red by an attachment a cancelled fan
    /// accepts, which would issue legs nothing cancels.
    #[test]
    fn a_cancelled_fan_refuses_its_engine_and_an_uncancelled_one_says_it_is_over() {
        let engine = engine();
        let canceller = canceller_of(engine);
        let fan = CancellableFan::new();
        fan.cancel();
        assert!(fan.is_cancelled());
        assert!(!fan.attach(canceller));
        drop(fan);
        assert!(engine.taken().is_empty(), "no engine was attached");

        let fan = CancellableFan::new();
        assert!(fan.attach(canceller));
        let key = fan.key();
        drop(fan);
        assert_eq!(engine.taken(), vec![(key, "over")]);
    }

    /// Fans lying in places of their own, on a token lying in its owner's: one dropped from the
    /// middle of the list is unlinked, and the cancel reaches exactly the others. Turned red by
    /// an unlink that leaves the dropped fan on the list.
    #[test]
    fn a_fan_dropped_from_the_middle_is_off_its_tokens_list() {
        let token = CancellationToken::new().expect("a token place is free");
        let engine = engine();
        let canceller = canceller_of(engine);
        let mut fans: Vec<Box<CancellableFan>> = (0..3).map(|_| Box::default()).collect();
        for fan in &fans {
            // SAFETY: each fan is its box's and is not moved; the token is dropped after them.
            assert!(unsafe { fan.register(TokenRef::placed(&token)) });
            assert!(fan.attach(canceller));
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

    /// A fan cancelled twice, by its owner and by its token, asks its engine to end its legs once,
    /// by its key. Turned red by a second cancel that reaches the engine again.
    #[test]
    fn a_fan_cancelled_twice_asks_its_engine_once() {
        let engine = engine();
        let fan = CancellableFan::new();
        assert!(fan.attach(canceller_of(engine)));
        let key = fan.key();
        fan.cancel();
        fan.cancel();
        assert_eq!(engine.taken(), vec![(key, "cancel")]);
        drop(fan);
        assert_eq!(
            engine.taken(),
            vec![(key, "cancel")],
            "a cancelled fan is not over again at its drop"
        );
    }
    /// What the engine-end canceller was told, with the engine it named.
    static TOLD: Mutex<Vec<(EngineAt, FanEnd)>> = Mutex::new(Vec::new());

    fn told(at: EngineAt, end: FanEnd) {
        TOLD.lock().unwrap().push((at, end));
    }

    /// A fan attached to an engine named in its crate's table hands that crate the name and the
    /// end: a cancel as a cancel of the fan's key, a drop uncancelled as the fan being over.
    /// Turned red by an engine end told of the wrong engine, or the two ends swapped.
    #[test]
    fn an_engine_named_in_its_crates_table_is_told_the_fans_end_through_its_crate() {
        let at = EngineAt {
            row: 3,
            generation: 8,
        };
        let cancelled = CancellableFan::new();
        assert!(cancelled.attach(Canceller::Engine { at, ends: told }));
        let key = cancelled.key();
        cancelled.cancel();
        let dropped = CancellableFan::new();
        assert!(dropped.attach(Canceller::Engine { at, ends: told }));
        let over = dropped.key();
        drop(dropped);
        assert_eq!(
            *TOLD.lock().unwrap(),
            vec![(at, FanEnd::Cancel(key)), (at, FanEnd::Over(over))]
        );
    }

    /// The kernel's table of tokens holds as many tokens as the build's limits let a process have
    /// gets pending, refuses the next, and takes a token's place back with its last count.
    ///
    /// # Control
    ///
    /// Every place up to the bound is the control. A table sized apart from the limits, or one
    /// that lends a held place, reds the count or the refusal.
    #[test]
    fn the_table_of_tokens_holds_one_per_pending_get_and_refuses_the_next() {
        static TABLE: StaticPlaces<CancellationToken, TOKEN_PLACES> = StaticPlaces::new();
        assert_eq!(
            TOKEN_PLACES,
            caps::ENGINE_ROWS * (caps::MAX_PENDING_QUERIES + caps::MAX_PENDING_LIVELINESS_GETS),
            "the bound is the gets a process can have pending"
        );
        let make = |place: NonNull<CancellationToken>| {
            // SAFETY: the place is its lodging's, valid for one token, holding none, never moved.
            unsafe { CancellationToken::init_in(place) }
        };
        let mut held = Vec::new();
        for _ in 0..TOKEN_PLACES {
            // SAFETY: `make` makes the whole token.
            let token = unsafe { lodge_in_table(&TABLE, make) };
            held.push(token.expect("CONTROL: a place up to the bound"));
        }
        // SAFETY: as above.
        let past = unsafe { lodge_in_table(&TABLE, make) };
        assert_eq!(past.err(), Some(NoPlace), "one past the bound is refused");
        drop(held.pop());
        // SAFETY: as above.
        let again = unsafe { lodge_in_table(&TABLE, make) };
        assert!(
            again.is_ok(),
            "a token's place goes back with its last count"
        );
    }
}

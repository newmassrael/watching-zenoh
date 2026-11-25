// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The MATCHING plane — pico `Z_FEATURE_MATCHING`: is anybody subscribed to
//! what this publisher publishes.
//!
//! Binds wz's already-active `session-matching` atom
//! (`Publisher::get_matching_status` / `Publisher::declare_matching_listener`)
//! through the engine's `declare_matching_listener`,
//! which is where the cross-face aggregation lives. No new protocol: the
//! verdict is read off the remote-subscriber declarations wz already tracks.
//!
//! ## Why this closes a program rather than a symbol
//!
//! `z_pub.c` is upstream's canonical publisher, and measured against wz's
//! cdylib it was missing exactly two exports — `z_closure_matching_status_move`
//! and `z_publisher_declare_background_matching_listener`. Both are in the
//! `-a` (add-matching-listener) arm, which the program links unconditionally
//! and calls only when the flag is passed. So the ENTIRE canonical publisher
//! was un-droppable-in over an optional feature's two symbols.
//!
//! The family goes out whole (poll, one-shot listener, background listener,
//! the closure constructors, the listener ownership family) rather than just
//! the two `z_pub.c` needs. Shipping only what a witness exercises is what
//! produced this crate's `z_put_options_default`-absent-while-`z_get_options_default`-present
//! asymmetry, and an asymmetric family fails to link for the NEXT program
//! instead of this one.
//!
//! ## A listener is its entity's write filter's
//!
//! pico registers a matching listener on the entity's write filter, so it counts
//! what the filter counts and goes when the filter goes. Every form here declares
//! it on the entity's `WriteFilter` (`write_filter.rs`), which
//! retracts it with the entity. pico's `*_declare_background_*` forms return no
//! handle: their listener lives as long as its entity. The one-shot form hands
//! the id back inside a `z_owned_matching_listener_t`, and
//! `z_undeclare_matching_listener` retracts it sooner.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};

use wz_capi_port::sync::Lock;
use wz_capi_port::{MatchId, MatchingSink};

use crate::session::Engine;

use crate::abi::handle_ref;
use crate::ffi::{catch, guarded, CClosure, HeldIn, InCallback};
use crate::object_slot::{count_in_entity, kept_at, retire_entity, Answering, Kind, Slot};
// A build of one engine calls the engine through its own type, so the port's trait is in scope.
#[cfg(not(feature = "engine-tokio"))]
use crate::prelude::*;
use crate::pubsub::{z_closure_drop_callback_t, z_loaned_publisher_t, PublisherState};
use crate::refusal::{refusal_code, Door};
use crate::result::{ZResult, Z_ERR_NULL, Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_OK};
use crate::write_filter::WriteFilter;
use alloc::sync::Arc;

/// pico `z_matching_status_t` — `{ bool matching }`, 1 B measured, field at
/// offset 0. Passed to the callback BY POINTER, so its layout is read by C.
#[repr(C)]
pub struct z_matching_status_t {
    /// Whether at least one remote declaration currently intersects the
    /// publisher's keyexpr.
    pub matching: bool,
}

/// pico `z_closure_matching_status_callback_t`:
/// `void call(const z_matching_status_t*, void*)`.
pub type z_closure_matching_status_callback_t =
    Option<unsafe extern "C" fn(*const z_matching_status_t, *mut c_void)>;

/// Owned matching-status closure (pico `z_owned_closure_matching_status_t`,
/// 24 B: `{ context, call, drop }`, the same shape as every other pico
/// closure).
#[repr(C)]
pub struct z_owned_closure_matching_status_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_matching_status_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Loaned matching-status closure, same layout.
#[repr(C)]
pub struct z_loaned_closure_matching_status_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_matching_status_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved matching-status closure (pico `z_moved_closure_matching_status_t`).
#[repr(C)]
pub struct z_moved_closure_matching_status_t {
    pub(crate) _this: z_owned_closure_matching_status_t,
}

impl z_owned_closure_matching_status_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            context: core::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

/// A C matching closure, kept in its listener's place ([`MatchingPlace`]) and called there by the
/// raw callback the engine holds ([`matching_sink_at`]).
///
/// The engine calls it from more than one thread (the thread that delivers, and the program's own
/// inside a declare, where an already-matching listener is told at once), never two calls at
/// once for one listener: the cooperative engine takes the callback out of the listener's row for
/// each call, and the tokio engine calls it under its aggregate's lock
/// (`wz_capi_core::faces::deliver_matching_flip`). Its `drop(context)` runs once, when the engine
/// lets the callback go after its last call.
type MatchingCClosure = CClosure<z_closure_matching_status_callback_t>;

/// Behind a `z_owned_matching_listener_t`: the listener's session and its id there, which the
/// listener's undeclare retracts. It lies in the listener's place, a place of the session's own
/// for the kind (`crate::object_slot::Kind::MatchingListener`).
pub(crate) struct MatchingListenerState {
    shared: Arc<Engine>,
    id: MatchId,
}

/// What a listener's place keeps past its handle: the C closure the engine calls, and the link
/// through which its entity's write filter reaches it ([`FilterListeners`]). Each is let go of
/// apart: the closure by the engine's release of the callback, the link by whichever of the
/// handle and the filter takes the listener off the filter's list.
pub(crate) struct MatchingKept {
    closure: MatchingCClosure,
    link: FilterLink,
}

/// A matching listener's place: its handle's state, which the handle lets go of (none for a
/// background listener, which has no handle), and what is kept past it; the last of the handle,
/// the closure and the filter's hold gives the place back (`crate::object_slot::Answering`).
pub(crate) type MatchingPlace = crate::object_slot::Answering<MatchingListenerState, MatchingKept>;

/// A listener's link in its entity's write filter's list ([`FilterListeners`]), reached only
/// under [`LISTS`]: the listener's id, which outlives its handle's state, the list it is on (null
/// once it is off), the next listener of that list, and the filter's hold of the listener's place,
/// which keeps the place standing while the filter can reach it.
struct FilterLink {
    id: MatchId,
    on: AtomicPtr<FilterListeners>,
    next: AtomicPtr<MatchingListenerState>,
    held: UnsafeCell<Option<HeldIn>>,
}

impl FilterLink {
    /// A link on no list, its id not known yet.
    fn unlinked() -> Self {
        Self {
            id: 0,
            on: AtomicPtr::new(core::ptr::null_mut()),
            next: AtomicPtr::new(core::ptr::null_mut()),
            held: UnsafeCell::new(None),
        }
    }
}

/// The one lock every write filter's list of its listeners is changed under. One for the
/// process rather than one in each filter: a listener's handle may be undeclared after its entity,
/// and must learn whether the filter still holds it without reaching a filter that may be gone.
/// Held for a few pointer moves; nothing is dropped or called under it.
static LISTS: Lock<()> = Lock::new(());

/// The matching listeners declared on one write filter, linked through their places, with no
/// memory of its own. The filter's drop retracts each one it still holds
/// ([`Self::retract_all`]); a listener's undeclare takes it off first ([`retract_listener`]).
/// The list lies in the filter, which lies in its entity's place and does not move while a
/// listener is on it.
#[derive(Default)]
pub(crate) struct FilterListeners {
    head: AtomicPtr<MatchingListenerState>,
}

/// The link of the listener whose state is at `object`.
///
/// # Safety
/// `object` is the object of a live [`MatchingPlace`].
unsafe fn link_of(object: *const MatchingListenerState) -> *mut FilterLink {
    // SAFETY: the caller's: the place keeps a `MatchingKept` past the object.
    unsafe {
        core::ptr::addr_of_mut!(
            (*crate::object_slot::kept_at::<MatchingListenerState, MatchingKept>(object)).link
        )
    }
}

impl FilterListeners {
    /// Put the listener at `object` on this list, holding its place for the list until it is
    /// taken off.
    ///
    /// # Safety
    /// `object` is the object of a live [`MatchingPlace`] whose owner has not let go of it, on no
    /// list, its link's id written; this list does not move while the listener is on it.
    unsafe fn link(&self, object: *mut MatchingListenerState) {
        // SAFETY: the caller's.
        let held = unsafe {
            crate::object_slot::hold_entity::<MatchingListenerState, MatchingKept>(object)
        };
        // SAFETY: the caller's: the link stands while the place does, and is reached under
        // `LISTS` alone from here.
        let link = unsafe { link_of(object) };
        LISTS.with(|_| {
            // SAFETY: as above; nothing else reads the hold while the listener is on no list.
            unsafe { *(*link).held.get() = Some(held) };
            // SAFETY: as above.
            let link = unsafe { &*link };
            link.on
                .store(core::ptr::from_ref(self).cast_mut(), Ordering::Relaxed);
            link.next
                .store(self.head.load(Ordering::Relaxed), Ordering::Relaxed);
            self.head.store(object, Ordering::Relaxed);
        });
    }

    /// Take the listener at `object` off this list, under `LISTS`.
    ///
    /// # Safety
    /// `LISTS` is held, and `object` is on this list.
    unsafe fn unlink(&self, object: *mut MatchingListenerState) {
        // SAFETY: the caller's: every listener on the list stands, held by it.
        let next = unsafe { &*link_of(object) }.next.load(Ordering::Relaxed);
        let mut at = &self.head;
        loop {
            let here = at.load(Ordering::Relaxed);
            if here.is_null() {
                return;
            }
            if here == object {
                at.store(next, Ordering::Relaxed);
                return;
            }
            // SAFETY: as above: `here` is on the list.
            at = unsafe { &(*link_of(here)).next };
        }
    }

    /// Retract every listener still on this list, for its filter's drop: each is taken off at
    /// once, then retracted from `engine`, waited for until its closure's `drop(context)` has run
    /// (unless this is inside a callback), and its place let go of by the list, which gives it
    /// back when its handle went first. A listener undeclared meanwhile waits for this.
    pub(crate) fn retract_all(&self, engine: &Engine) {
        let mut at = LISTS.with(|_| {
            let first = self.head.load(Ordering::Relaxed);
            self.head.store(core::ptr::null_mut(), Ordering::Relaxed);
            let mut each = first;
            while !each.is_null() {
                // SAFETY: `each` is on the list, so its place stands, held by it.
                let link = unsafe { &*link_of(each) };
                link.on.store(core::ptr::null_mut(), Ordering::Relaxed);
                each = link.next.load(Ordering::Relaxed);
            }
            first
        });
        while !at.is_null() {
            let object = at;
            // SAFETY: the list's hold keeps the place standing until it is dropped below, and no
            // one else reads the link of a listener taken off its list by its filter.
            let link = unsafe { link_of(object) };
            // SAFETY: as above.
            let (id, next) = unsafe { ((*link).id, (*link).next.load(Ordering::Relaxed)) };
            at = next;
            engine.undeclare_matching_listener(id);
            // SAFETY: as above; the list's own hold is the one left once the closure went.
            unsafe {
                crate::object_slot::closures_of::<MatchingListenerState, MatchingKept>(object)
                    .wait_at_most(1);
            }
            // SAFETY: as above; taken out once, here.
            let held = unsafe { (*(*link).held.get()).take() };
            // The last use of the place: this may give it back.
            drop(held);
        }
    }
}

/// Undeclare the listener whose state is at `object` and let go of its handle: taken off its
/// filter's list when still on it, retracted from its session, waited for until its closure's
/// `drop(context)` has run (unless this is inside a callback, or its filter is retracting it
/// too, which this waits for), and its state dropped; the place goes back with the last of the
/// handle, the closure and the filter's hold.
///
/// # Safety
/// `object` is a live handle of a [`MatchingPlace`], let go of once, here.
unsafe fn retract_listener(object: *mut MatchingListenerState) {
    // SAFETY: the caller's: the place stands while its owner holds it.
    let link = unsafe { link_of(object) };
    let held = LISTS.with(|_| {
        // SAFETY: as above; the link is reached under `LISTS`.
        let on = unsafe { &*link }.on.load(Ordering::Relaxed);
        if on.is_null() {
            // Its filter took it off and lets go of its hold itself.
            return None;
        }
        // SAFETY: a list a listener is on stands until its filter takes it off, under `LISTS`,
        // which this holds; the listener is on it.
        unsafe {
            (*on).unlink(object);
            (*link).on.store(core::ptr::null_mut(), Ordering::Relaxed);
            (*(*link).held.get()).take()
        }
    });
    // SAFETY: the caller's: the state stands until `retire_listener` below.
    unsafe { (*object).shared.undeclare_matching_listener((*object).id) };
    // The place stands with its owner, so the filter's hold may go first.
    drop(held);
    // SAFETY: the caller's; the owner lets go of the place once, here.
    unsafe {
        crate::object_slot::closures_of::<MatchingListenerState, MatchingKept>(object).wait_none();
        retire_listener(object);
    }
}

/// Let go of a listener's state for its owner ([`retire_entity`]): one body for the undeclare,
/// the declare refused and the background declare, which would each carry their own copy of the
/// release, its lock and the place given back.
///
/// # Safety
/// As [`retire_entity`]'s, for the state of a [`MatchingPlace`].
#[inline(never)]
unsafe fn retire_listener(object: *mut MatchingListenerState) {
    // SAFETY: the caller's.
    unsafe { retire_entity::<MatchingListenerState, MatchingKept>(object) };
}

/// Owned matching listener (pico `z_owned_matching_listener_t`, 24 B measured).
#[repr(C)]
pub struct z_owned_matching_listener_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 2],
}

/// Loaned matching listener (pico `z_loaned_matching_listener_t`).
#[repr(C)]
pub struct z_loaned_matching_listener_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 2],
}

/// Moved matching listener (pico `z_moved_matching_listener_t`).
#[repr(C)]
pub struct z_moved_matching_listener_t {
    pub(crate) _this: z_owned_matching_listener_t,
}

impl z_owned_matching_listener_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            _pad: [core::ptr::null_mut(); 2],
        }
    }
}

// --- closure exports -------------------------------------------------------

/// Build an owned matching-status closure (pico `z_closure_matching_status`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status(
    closure: *mut z_owned_closure_matching_status_t,
    call: z_closure_matching_status_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        if closure.is_null() {
            return Z_ERR_NULL;
        }
        *closure = z_owned_closure_matching_status_t {
            context,
            call,
            drop,
        };
        Z_OK
    })
}

/// Null an owned matching-status closure (pico
/// `z_internal_closure_matching_status_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_matching_status_null(
    closure: *mut z_owned_closure_matching_status_t,
) {
    if !closure.is_null() {
        *closure = z_owned_closure_matching_status_t::null_value();
    }
}

/// Whether an owned matching-status closure carries a callback (pico
/// `z_internal_closure_matching_status_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_matching_status_check(
    closure: *const z_owned_closure_matching_status_t,
) -> bool {
    !closure.is_null() && (*closure).call.is_some()
}

/// Borrow an owned matching-status closure (pico
/// `z_closure_matching_status_loan`) — offset-0 identity, as pico's macro emits.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_loan(
    closure: *const z_owned_closure_matching_status_t,
) -> *const z_loaned_closure_matching_status_t {
    closure as *const z_loaned_closure_matching_status_t
}

/// Move an owned matching-status closure (pico
/// `z_closure_matching_status_move`) — the identity cast pico's macro emits.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_move(
    closure: *mut z_owned_closure_matching_status_t,
) -> *mut z_moved_closure_matching_status_t {
    closure as *mut z_moved_closure_matching_status_t
}

/// Take a moved matching-status closure (pico
/// `z_closure_matching_status_take`), nulling the source — pico's
/// consume-on-take contract, so the `drop` runs exactly once.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_take(
    closure: *mut z_owned_closure_matching_status_t,
    src: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| {
        if closure.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        *closure = core::mem::replace(
            &mut (*src)._this,
            z_owned_closure_matching_status_t::null_value(),
        );
        Z_OK
    })
}

/// Release a matching-status closure (pico `z_closure_matching_status_drop`),
/// invoking the caller's `drop(context)` once.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_drop(
    closure: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        let taken = core::mem::replace(
            &mut (*closure)._this,
            z_owned_closure_matching_status_t::null_value(),
        );
        if let Some(dropfn) = taken.drop {
            dropfn(taken.context);
        }
        Z_OK
    })
}

/// Invoke a matching-status closure (pico `z_closure_matching_status_call`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_call(
    closure: *const z_loaned_closure_matching_status_t,
    status: *const z_matching_status_t,
) {
    if closure.is_null() {
        return;
    }
    if let Some(call) = (*closure).call {
        call(status, (*closure).context);
    }
}

// --- matching-listener ownership family ------------------------------------

/// Null an owned matching listener (pico `z_internal_matching_listener_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_matching_listener_null(
    listener: *mut z_owned_matching_listener_t,
) {
    if !listener.is_null() {
        *listener = z_owned_matching_listener_t::null_value();
    }
}

/// Whether an owned matching listener is live (pico
/// `z_internal_matching_listener_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_matching_listener_check(
    listener: *const z_owned_matching_listener_t,
) -> bool {
    !listener.is_null() && !(*listener).handle.is_null()
}

/// Borrow an owned matching listener (pico `z_matching_listener_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_matching_listener_loan(
    listener: *const z_owned_matching_listener_t,
) -> *const z_loaned_matching_listener_t {
    listener as *const z_loaned_matching_listener_t
}

/// Borrow an owned matching listener mutably (pico
/// `z_matching_listener_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_matching_listener_loan_mut(
    listener: *mut z_owned_matching_listener_t,
) -> *mut z_loaned_matching_listener_t {
    listener as *mut z_loaned_matching_listener_t
}

/// Move an owned matching listener (pico `z_matching_listener_move`).
#[no_mangle]
pub unsafe extern "C" fn z_matching_listener_move(
    listener: *mut z_owned_matching_listener_t,
) -> *mut z_moved_matching_listener_t {
    listener as *mut z_moved_matching_listener_t
}

/// Take a moved matching listener (pico `z_matching_listener_take`).
#[no_mangle]
pub unsafe extern "C" fn z_matching_listener_take(
    listener: *mut z_owned_matching_listener_t,
    src: *mut z_moved_matching_listener_t,
) -> ZResult {
    guarded(|| {
        if listener.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        *listener =
            core::mem::replace(&mut (*src)._this, z_owned_matching_listener_t::null_value());
        Z_OK
    })
}

/// Release a matching listener without retracting the watch (pico
/// `z_matching_listener_drop` is `z_undeclare_matching_listener`).
#[no_mangle]
pub unsafe extern "C" fn z_matching_listener_drop(
    listener: *mut z_moved_matching_listener_t,
) -> ZResult {
    z_undeclare_matching_listener(listener)
}

// --- publisher-side exports ------------------------------------------------

/// Poll the current matching status (pico `z_publisher_get_matching_status`).
///
/// pico answers it from the publisher's write filter
/// (`vendor/zenoh-pico/src/api/api.c` @
/// `matching_status->matching = !_z_write_filter_active(&publisher->_filter);`), and so
/// does this: `true` when what the filter counts has a match — a connected peer's
/// subscriber, and with `local-subscriber` the session's own for a publisher whose
/// destination admits it. The listener counts the same, so the poll and the callback
/// cannot disagree.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_get_matching_status(
    publisher: *const z_loaned_publisher_t,
    matching_status: *mut z_matching_status_t,
) -> ZResult {
    guarded(|| {
        if matching_status.is_null() {
            return Z_ERR_NULL;
        }
        let state = match handle_ref::<z_loaned_publisher_t, PublisherState>(publisher) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        (*matching_status).matching = state.filter_matches();
        Z_OK
    })
}

/// Declare a matching listener, handing back a handle (pico
/// `z_publisher_declare_matching_listener`).
///
/// The moved closure is consumed on EVERY path including the failure ones —
/// pico's ownership transfer is unconditional once the call is made, so an
/// early return that skipped the release would leak the caller's context.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_declare_matching_listener(
    publisher: *const z_loaned_publisher_t,
    listener: *mut z_owned_matching_listener_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| {
        declare_on_filter(
            handle_ref::<z_loaned_publisher_t, PublisherState>(publisher).map(|s| s.filter()),
            Some(listener),
            callback,
        )
    })
}

/// Declare a session-lifetime matching listener with no handle (pico
/// `z_publisher_declare_background_matching_listener`).
#[no_mangle]
pub unsafe extern "C" fn z_publisher_declare_background_matching_listener(
    publisher: *const z_loaned_publisher_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| {
        declare_on_filter(
            handle_ref::<z_loaned_publisher_t, PublisherState>(publisher).map(|s| s.filter()),
            None,
            callback,
        )
    })
}

/// Retract a matching listener (pico `z_undeclare_matching_listener`): taken off its entity's write
/// filter, retracted from its session, and waited for until its closure's `drop(context)` has
/// run, as pico's undeclare does, unless it is made from inside a callback.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_matching_listener(
    listener: *mut z_moved_matching_listener_t,
) -> ZResult {
    guarded(|| {
        if listener.is_null() {
            return Z_OK;
        }
        let handle = (*listener)._this.handle;
        if handle.is_null() {
            return Z_OK;
        }
        (*listener)._this = z_owned_matching_listener_t::null_value();
        retract_listener(handle.cast::<MatchingListenerState>());
        Z_OK
    })
}

/// The one body of every matching listener declare — a publisher's, an advanced
/// publisher's and a querier's, each with a handle and in the background: consume the
/// moved closure, keep it in a place of the session's for the listener, declare the listener on
/// the entity's write filter with a callback that calls the closure there
/// ([`WriteFilter::declare_matching_listener`]), which is where pico registers it, and put the
/// listener on the filter's list, which retracts it with the entity.
///
/// `filter` is the entity's, `None` when the entity's handle was not a live one.
/// `listener` is the handle slot, or `None` for the BACKGROUND form, whose listener has no
/// handle and lives as long as its entity. A null slot is the background form too, as pico's
/// background door is its handle door with a null slot (`vendor/zenoh-pico/src/api/api.c` @
/// `return z_publisher_declare_matching_listener(publisher, NULL, callback);`).
///
/// One body rather than one per form, so the closure-consumption contract and the place cannot
/// drift between them.
///
/// Refused with nothing declared: a null closure or entity with `Z_ERR_NULL`, a
/// session with every listener place held with `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, and a listener the
/// engine refuses with the code pico's door answers for the refusal ([`refusal_code`]): a
/// listener that would never be called must not read as `Z_OK`. The handle slot is left null and
/// the closure's `drop(context)` has run on each of them.
///
/// # Safety
/// `listener`'s slot must be null or valid and writable; `callback` must be null or a
/// valid moved closure, which is consumed on every path.
pub(crate) unsafe fn declare_on_filter(
    filter: Option<&WriteFilter>,
    listener: Option<*mut z_owned_matching_listener_t>,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    let slot = listener.filter(|slot| !slot.is_null());
    if let Some(slot) = slot {
        *slot = z_owned_matching_listener_t::null_value();
    }
    if callback.is_null() {
        return Z_ERR_NULL;
    }
    // Taken first, so every refusal below drops it, running the caller's `drop(context)`.
    let taken = core::mem::replace(
        &mut (*callback)._this,
        z_owned_closure_matching_status_t::null_value(),
    );
    let closure = MatchingCClosure::uncounted(taken.context, taken.call, taken.drop);
    let Some(filter) = filter else {
        return Z_ERR_NULL;
    };
    let Some(place) = Slot::<MatchingPlace>::take_entity(filter.engine(), Kind::MatchingListener)
    else {
        return Z_ERR_SYSTEM_OUT_OF_MEMORY;
    };
    let object = place
        .fill(Answering::keeping(
            MatchingListenerState {
                shared: Arc::clone(filter.engine()),
                id: 0,
            },
            MatchingKept {
                closure,
                link: FilterLink::unlinked(),
            },
        ))
        .cast::<MatchingListenerState>();
    // The closure lies in the place now, counted there before the engine can call it or let it go.
    let kept = kept_at::<MatchingListenerState, MatchingKept>(object);
    count_in_entity::<MatchingListenerState, MatchingKept, _>(object, &mut (*kept).closure);
    let id = match filter.declare_matching_listener(matching_sink_at(object)) {
        Ok(id) => id,
        Err(refused) => {
            // The refusal let go of the callback, and so of the closure; the place goes back
            // with the state.
            retire_listener(object);
            return refusal_code(refused, Door::MatchingListener);
        }
    };
    // Written before the listener is on the list, which is where the id is read from.
    (*object).id = id;
    (*link_of(object)).id = id;
    filter.listeners().link(object);
    match slot {
        Some(slot) => {
            *slot = z_owned_matching_listener_t {
                handle: object.cast::<c_void>(),
                _pad: [core::ptr::null_mut(); 2],
            };
        }
        // No handle will undeclare it: its owner lets go of it at once, and the place stays with
        // the filter's hold and the closure until the filter retracts it.
        None => retire_listener(object),
    }
    Z_OK
}

/// Hand `matching` to the C callback of `closure`, marked as one of the program's callbacks: an
/// undeclare the callback makes of its own listener, or a drop of the entity that holds it, then
/// leaves the closure to be let go of as the callback returns instead of waiting on itself
/// (`crate::ffi::OpenClosures::wait_none`). An unwind out of the C callback is caught here
/// rather than crossing into the thread that delivers.
fn hand_status(closure: &MatchingCClosure, matching: bool) {
    let Some(call) = closure.call else {
        return;
    };
    let status = z_matching_status_t { matching };
    let ctx = closure.context.0;
    let Some(_in_callback) = InCallback::enter() else {
        return;
    };
    // SAFETY: `context` is the caller's, alive until `drop` runs, which comes after the last
    // call (`MatchingCClosure`).
    let _ = catch(|| unsafe {
        call(&status, ctx);
    });
}

/// The callback the engine holds for the listener whose state is at `object`: a raw one whose
/// context is the place, calling the closure kept there through a shared borrow, and whose release
/// takes the closure out and drops it once, after the last call: its C `drop(context)` runs, and
/// the place goes back if the handle and the filter let go of it first. Nothing is allocated.
///
/// # Safety
/// `object` is the object of a live place filled for an `Answering<T, MatchingKept>`
/// (`crate::object_slot::Answering`) whose closure is counted in it and taken out by nothing but
/// the callback made here.
unsafe fn matching_sink_at<T>(object: *mut T) -> MatchingSink {
    /// # Safety
    /// `context` is the object of a place whose closure the release has not taken out.
    unsafe fn call<T>(context: *mut c_void, matching: bool) {
        // SAFETY: the caller's: the closure stands in the place; only the closure is borrowed, as
        // the link beside it is written apart.
        let closure = unsafe {
            &*core::ptr::addr_of!((*kept_at::<T, MatchingKept>(context.cast::<T>())).closure)
        };
        hand_status(closure, matching);
    }
    /// # Safety
    /// As `call`'s, and nothing calls either again.
    unsafe fn release<T>(context: *mut c_void) {
        // SAFETY: the caller's: the closure is taken out once, here, and dropped out of the place,
        // as its drop may give the place back.
        let closure = unsafe {
            core::ptr::read(core::ptr::addr_of!(
                (*kept_at::<T, MatchingKept>(context.cast::<T>())).closure
            ))
        };
        drop(closure);
    }
    // SAFETY: `call` borrows the closure in the place, which the engine never does from two
    // threads at once for one listener (`MatchingCClosure`); `release` takes it out once, after
    // the last call, and the place stands until then, as the closure is counted in it.
    unsafe { MatchingSink::raw(call::<T>, object.cast::<c_void>(), Some(release::<T>)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ABI sizes a C program stack-allocates through pico's own header,
    /// measured against the vendored headers and pinned here so padding drift
    /// fails the build rather than corrupting the caller's frame.
    ///
    /// The closure and the listener are three words each, 24 B on a 64-bit host.
    #[test]
    fn matching_abi_sizes_match_pico() {
        let three_words = 3 * core::mem::size_of::<*mut c_void>();
        assert_eq!(
            core::mem::size_of::<z_owned_closure_matching_status_t>(),
            three_words
        );
        assert_eq!(
            core::mem::size_of::<z_moved_closure_matching_status_t>(),
            three_words
        );
        assert_eq!(
            core::mem::size_of::<z_owned_matching_listener_t>(),
            three_words
        );
        assert_eq!(
            core::mem::size_of::<z_moved_matching_listener_t>(),
            three_words
        );
        // `z_matching_status_t` is `{ bool }` — 1 B, field at offset 0, and it
        // crosses the boundary BY POINTER so C reads this layout directly.
        assert_eq!(core::mem::size_of::<z_matching_status_t>(), 1);
    }

    /// `z_closure_matching_status_call` reaches the C callback with the status
    /// it was handed, and a null closure is a silent no-op rather than a crash
    /// (pico tolerates an unset closure).
    #[test]
    fn closure_call_reaches_the_callback_and_tolerates_null() {
        use core::sync::atomic::{AtomicI32, Ordering};
        static SEEN: AtomicI32 = AtomicI32::new(-1);
        unsafe extern "C" fn cb(status: *const z_matching_status_t, _ctx: *mut c_void) {
            SEEN.store(i32::from((*status).matching), Ordering::SeqCst);
        }

        let mut closure = z_owned_closure_matching_status_t::null_value();
        unsafe {
            assert_eq!(
                z_closure_matching_status(&mut closure, Some(cb), None, core::ptr::null_mut()),
                Z_OK
            );
            assert!(z_internal_closure_matching_status_check(&closure));

            let status = z_matching_status_t { matching: true };
            z_closure_matching_status_call(z_closure_matching_status_loan(&closure), &status);
            assert_eq!(SEEN.load(Ordering::SeqCst), 1);

            let status = z_matching_status_t { matching: false };
            z_closure_matching_status_call(z_closure_matching_status_loan(&closure), &status);
            assert_eq!(SEEN.load(Ordering::SeqCst), 0);

            // Null closure: no call, no crash.
            z_closure_matching_status_call(core::ptr::null(), &status);
            assert_eq!(SEEN.load(Ordering::SeqCst), 0);
        }
    }

    /// `move` / `loan` are pointer identity and `take` NULLS the source — the
    /// consume-once contract that keeps the C `drop(context)` from running
    /// twice.
    #[test]
    fn closure_move_is_identity_and_take_nulls_the_source() {
        let mut closure = z_owned_closure_matching_status_t::null_value();
        unsafe extern "C" fn cb(_s: *const z_matching_status_t, _c: *mut c_void) {}
        unsafe {
            z_closure_matching_status(&mut closure, Some(cb), None, 0x1234 as *mut c_void);
            let p = &mut closure as *mut z_owned_closure_matching_status_t;
            assert_eq!(z_closure_matching_status_move(p) as *mut _, p);
            assert_eq!(z_closure_matching_status_loan(p) as *const _, p as *const _);

            let mut dest = z_owned_closure_matching_status_t::null_value();
            assert_eq!(
                z_closure_matching_status_take(&mut dest, z_closure_matching_status_move(p)),
                Z_OK
            );
            assert!(dest.call.is_some(), "take moves the callback across");
            assert_eq!(dest.context, 0x1234 as *mut c_void);
            assert!(
                !z_internal_closure_matching_status_check(p),
                "take must NULL the source so drop cannot run twice"
            );
        }
    }

    /// The caller's `drop(context)` runs exactly once on
    /// `z_closure_matching_status_drop`, and a second drop of the same (now
    /// nulled) moved closure does not run it again.
    #[test]
    fn closure_drop_runs_the_caller_deleter_exactly_once() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn dropper(_ctx: *mut c_void) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
        unsafe extern "C" fn cb(_s: *const z_matching_status_t, _c: *mut c_void) {}

        let mut closure = z_owned_closure_matching_status_t::null_value();
        unsafe {
            z_closure_matching_status(&mut closure, Some(cb), Some(dropper), core::ptr::null_mut());
            let moved = z_closure_matching_status_move(&mut closure);
            assert_eq!(z_closure_matching_status_drop(moved), Z_OK);
            assert_eq!(DROPS.load(Ordering::SeqCst), 1);
            assert_eq!(z_closure_matching_status_drop(moved), Z_OK);
            assert_eq!(
                DROPS.load(Ordering::SeqCst),
                1,
                "a re-drop of a nulled closure must not re-run the deleter"
            );
        }
    }
    /// The callback a listener's engine holds hands each status to the C callback kept in the
    /// listener's place, with the program's context, and letting it go takes the closure out and
    /// runs the C drop once. Turned red by a callback that calls nothing, or one whose release is
    /// not the closure's drop.
    #[test]
    fn a_listeners_callback_calls_the_c_closure_and_drops_it_once() {
        use core::sync::atomic::AtomicUsize;
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn cb(status: *const z_matching_status_t, ctx: *mut c_void) {
            if (*status).matching && ctx as usize == 0x5a {
                SEEN.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe extern "C" fn dropper(ctx: *mut c_void) {
            if ctx as usize == 0x5a {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        let closure = MatchingCClosure::uncounted(0x5a as *mut c_void, Some(cb), Some(dropper));
        let mut place = Answering::keeping(
            0_u8,
            MatchingKept {
                closure,
                link: FilterLink::unlinked(),
            },
        );
        // SAFETY: `place` holds an `Answering<u8, MatchingKept>` that outlives the callback, whose
        // closure only the callback takes out.
        let sink = unsafe { matching_sink_at(core::ptr::from_mut(&mut place).cast::<u8>()) };
        sink.call(true);
        sink.call(true);
        assert_eq!(SEEN.load(Ordering::SeqCst), 2);
        assert_eq!(DROPS.load(Ordering::SeqCst), 0);
        drop(sink);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1, "the C drop ran once");
    }

    /// How many listener places `engine` has free: each claimed, then all given back.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    fn free_places(engine: &Arc<Engine>) -> usize {
        let claimed: crate::prelude::Vec<Slot<u64>> =
            core::iter::from_fn(|| Slot::<u64>::take_entity(engine, Kind::MatchingListener))
                .collect();
        claimed.len()
    }

    /// A listener's place taken from `engine` and filled as a declare fills it, on no list.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    fn placed(engine: &Arc<Engine>) -> *mut MatchingListenerState {
        Slot::<MatchingPlace>::take_entity(engine, Kind::MatchingListener)
            .expect("a listener's place")
            .fill(Answering::keeping(
                MatchingListenerState {
                    shared: Arc::clone(engine),
                    id: 0,
                },
                MatchingKept {
                    closure: MatchingCClosure::uncounted(core::ptr::null_mut(), None, None),
                    link: FilterLink::unlinked(),
                },
            ))
            .cast::<MatchingListenerState>()
    }

    /// A listener's place stands while its filter's list holds it: a background listener, whose
    /// owner goes at once, keeps its place until the filter retracts it; one undeclared by its
    /// handle is taken off the list and gives its place back then. One listener at a time, as the
    /// session opens under the pico preset, whose `MAX_MATCHING_LISTENERS` admits one. Turned
    /// red by a list that holds no place (a place given back while the filter can still reach
    /// it), or one an undeclared listener stays on (a place never given back).
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn a_listeners_place_stands_while_its_filter_holds_it() {
        use crate::session::{
            engine_held, listening_on_loopback, session_handle, z_session_drop, z_session_loan,
            z_session_move,
        };

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        let places = free_places(&engine);
        assert!(places >= 1, "the session's limit admits a listener");
        let list = FilterListeners::default();

        let background = placed(&engine);
        // SAFETY: the place was filled just above and is on no list; `list` stays here while it
        // is on it, and its owner lets go of it once.
        unsafe {
            list.link(background);
            retire_entity::<MatchingListenerState, MatchingKept>(background);
        }
        assert_eq!(
            free_places(&engine),
            places - 1,
            "the list holds the background one"
        );
        list.retract_all(Arc::as_ref(&engine));
        assert_eq!(
            free_places(&engine),
            places,
            "the filter's retraction gave the background listener's place back"
        );
        assert!(list.head.load(Ordering::Relaxed).is_null());

        let handled = placed(&engine);
        // SAFETY: as above, for a place whose owner keeps it.
        unsafe { list.link(handled) };
        assert_eq!(
            free_places(&engine),
            places - 1,
            "the listener holds its place"
        );
        // SAFETY: `handled` is a live handle, let go of once, here.
        unsafe { retract_listener(handled) };
        assert_eq!(
            free_places(&engine),
            places,
            "the undeclared listener's place went back"
        );
        assert!(
            list.head.load(Ordering::Relaxed).is_null(),
            "the undeclare took the listener off its filter's list"
        );

        drop(engine);
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// Two listeners on one filter, under a session whose config states room for two: one
    /// undeclared by its handle is taken off the list and gives its place back, leaving the
    /// background one on it, whose place stands until the filter retracts it. Turned red by an
    /// undeclare that takes the other listener off with it, or leaves its own on the list.
    #[cfg(all(
        not(feature = "engine-tokio"),
        feature = "peer",
        feature = "config-document"
    ))]
    #[test]
    fn an_undeclared_listener_leaves_the_others_on_its_filter() {
        use crate::config_policy::wz_ext_config_document;
        use crate::session::{
            engine_held, listening_on_loopback_with, session_handle, z_session_drop,
            z_session_loan, z_session_move,
        };
        use wz_session_core::limit_binding::Quota;
        use wz_session_core::limits::SessionLimits;

        // A build whose domain keeps the limit to its own value refuses the statement this needs;
        // that refusal is the document door's own test.
        if SessionLimits::defaults()
            .select_max_matching_listeners(Quota::at_most(2))
            .is_err()
        {
            return;
        }
        let mut session = listening_on_loopback_with(|config| {
            // SAFETY: the config is live and the document a NUL-terminated string.
            let stated = unsafe {
                wz_ext_config_document(
                    config,
                    c"{ wz: { limits: { MAX_MATCHING_LISTENERS: 2 } } }".as_ptr(),
                )
            };
            assert_eq!(stated, Z_OK);
        });
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        let places = free_places(&engine);
        assert!(places >= 2, "the stated limit admits two listeners");

        let list = FilterListeners::default();
        let background = placed(&engine);
        let handled = placed(&engine);
        // SAFETY: each place was filled just above and is on no list; `list` stays here while
        // they are on it, and each owner lets go of its place once.
        unsafe {
            list.link(background);
            retire_entity::<MatchingListenerState, MatchingKept>(background);
            list.link(handled);
        }
        assert_eq!(
            free_places(&engine),
            places - 2,
            "the list holds the background one"
        );
        // SAFETY: `handled` is a live handle, let go of once, here.
        unsafe { retract_listener(handled) };
        assert_eq!(
            free_places(&engine),
            places - 1,
            "the undeclared listener's place went back; the background one's stands"
        );
        assert_eq!(
            list.head.load(Ordering::Relaxed),
            background,
            "the background listener is left on the list"
        );
        list.retract_all(Arc::as_ref(&engine));
        assert_eq!(
            free_places(&engine),
            places,
            "the filter's retraction gave the background listener's place back"
        );
        assert!(list.head.load(Ordering::Relaxed).is_null());

        drop(engine);
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }
}

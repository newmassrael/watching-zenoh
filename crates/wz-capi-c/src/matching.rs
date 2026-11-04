// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Matching listeners — "does anyone subscribe to what I publish?"
//!
//! ## The verdict is AGGREGATED across faces, and it has to be
//!
//! wz holds N sessions where zenoh-c holds one, so a per-face pass-through would
//! print "no more matching subscribers" the moment ONE peer went away while
//! another was still subscribed — the opposite of the truth. The aggregation (an
//! OR across faces, delivered once when the session-level verdict FLIPS) lives in
//! [`declare_matching_listener`](wz_capi_core::faces::SharedSession::declare_matching_listener)
//! and is shared with the zenoh-pico ABI. This module is the zenoh-c spelling.
//!
//! ## BOTH forms are exported since R311y564
//!
//! `z_pub.c` calls `z_publisher_declare_background_matching_listener`, whose
//! listener "will be automatically dropped when the publisher is dropped", and
//! that was the only form here while the crate's scope rule was an upstream
//! PROGRAM. The census question is a different one — `libzenohc.so` DEFINES the
//! owned family, so a C program naming it did not link — so
//! [`z_publisher_declare_matching_listener`] and the querier twin now ship with
//! an owned [`z_owned_matching_listener_t`], its undeclare, and the two polls
//! ([`z_publisher_get_matching_status`] / [`z_querier_get_matching_status`]).
//!
//! Retiring the listener when its publisher drops is `MatchingHold`'s `Drop`,
//! which the publisher state owns — so the two cannot drift, the same discipline
//! the liveliness token uses for its retraction.

use std::ffi::c_void;
use std::sync::Arc;

use wz_capi_core::faces::{MatchId, SharedSession};

use crate::abi::{z_closure_drop_callback_t, z_loaned_publisher_t};
use crate::ffi::{guard_val, guarded, CClosure as FfiClosure};
use crate::result::{ZResult, Z_ENULL, Z_OK};

/// zenoh-c `z_matching_status_t` (`zenoh_commons.h:511-516`) — one `bool`.
///
/// Passed to the C callback BY POINTER, so its single field's offset is the whole
/// layout contract.
#[repr(C)]
pub struct z_matching_status_t {
    /// `true` while at least one matching entity exists.
    pub matching: bool,
}

const _: () = {
    assert!(std::mem::size_of::<z_matching_status_t>() == 1);
};

/// zenoh-c `z_closure_matching_status_callback_t`.
pub type z_closure_matching_status_callback_t =
    Option<unsafe extern "C" fn(*const z_matching_status_t, *mut c_void)>;

/// Owned matching-status closure (zenoh-c `z_owned_closure_matching_status_t`,
/// `zenoh_commons.h:523-527`).
///
/// TRANSPARENT — written directly by the C `z_closure` macro, so the field ORDER
/// is part of the ABI and not merely the size.
#[repr(C)]
pub struct z_owned_closure_matching_status_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_matching_status_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Loaned matching-status closure (zenoh-c
/// `z_loaned_closure_matching_status_t`, `zenoh_commons.h:532-536`).
///
/// Upstream declares it as three bare `size_t`s, which is the same 24-byte
/// footprint as the owned form — so [`z_closure_matching_status_loan`] is a
/// pointer cast and the fields are written out here rather than as a blob, for
/// the same reason the owned one is.
///
/// R311y568 — the type and its four functions were missing entirely, so a C
/// program that CALLED a matching-status closure (rather than only handing one
/// to `z_publisher_declare_matching_listener`) failed to link.
#[repr(C)]
pub struct z_loaned_closure_matching_status_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_matching_status_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved matching-status closure.
#[repr(C)]
pub struct z_moved_closure_matching_status_t {
    pub(crate) _this: z_owned_closure_matching_status_t,
}

impl z_owned_closure_matching_status_t {
    /// The gravestone: no context, no callbacks.
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<z_owned_closure_matching_status_t>() == 24);
    assert!(std::mem::align_of::<z_owned_closure_matching_status_t>() == 8);
    assert!(std::mem::size_of::<z_moved_closure_matching_status_t>() == 24);
    // The loan is a CAST, so the two footprints must agree exactly — asserted
    // rather than assumed, because the owned form's fields are typed while
    // upstream's loaned one is three bare words.
    assert!(std::mem::size_of::<z_loaned_closure_matching_status_t>() == 24);
    assert!(std::mem::align_of::<z_loaned_closure_matching_status_t>() == 8);
};

// --- R311y568: the closure's own four entry points --------------------------

/// Borrow a matching-status closure (zenoh-c `z_closure_matching_status_loan`).
///
/// A pointer CAST — see [`z_loaned_closure_matching_status_t`].
///
/// # Safety
/// `closure` must be null or a valid owned matching-status closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_loan(
    closure: *const z_owned_closure_matching_status_t,
) -> *const z_loaned_closure_matching_status_t {
    closure as *const z_loaned_closure_matching_status_t
}

/// Invoke a matching-status closure (zenoh-c `z_closure_matching_status_call`).
///
/// Calling an uninitialised closure is a NO-OP, which is upstream's documented
/// behaviour for every closure family.
///
/// # Safety
/// `closure` must be null or a valid loaned closure; `matching_status` must be
/// null or a valid status struct.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_call(
    closure: *const z_loaned_closure_matching_status_t,
    matching_status: *const z_matching_status_t,
) {
    guard_val((), || {
        if closure.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let (call, context) = unsafe { ((*closure).call, (*closure).context) };
        let Some(call) = call else {
            return;
        };
        // SAFETY: the caller's function pointer; an unwind back across
        // `extern "C"` is UB, so it is caught.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            call(matching_status, context);
        }));
    });
}

/// `true` iff the owned closure holds a callback (zenoh-c
/// `z_internal_closure_matching_status_check`).
///
/// # Safety
/// `this_` must be null or a valid owned matching-status closure.
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_matching_status_check(
    this_: *const z_owned_closure_matching_status_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && unsafe { (*this_).call }.is_some()
    })
}

/// Zero an owned matching-status closure (zenoh-c
/// `z_internal_closure_matching_status_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned closure.
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_matching_status_null(
    this_: *mut z_owned_closure_matching_status_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_closure_matching_status_t::null_value() };
    }
}

/// The Rust-side wrapper a matching listener's callback holds.
pub(crate) type CMatchClosure = FfiClosure<z_closure_matching_status_callback_t>;

// SAFETY: the aggregated verdict is delivered from the drive task while the
// registry holds the aggregate mutex across the C call, so `call` is never
// re-entered concurrently on one context. `drop` runs only through the single
// owner the registry keeps (R311y535 made the sink OWNED rather than cloned
// precisely so that release is synchronous and single), which cannot overlap a
// live `call` for the same reason.
unsafe impl Sync for CMatchClosure {}

/// Retires a background matching listener when its publisher drops.
///
/// The retraction lives here rather than in the publisher's own `Drop` body so
/// that a publisher WITHOUT a listener costs nothing and one WITH a listener
/// cannot forget — the same reason the liveliness token's retraction is in
/// `TokenState::drop`.
pub(crate) struct MatchingHold {
    /// Held for its drop, which retires the listener.
    _target: MatchTarget,
}

/// What a matching listener is declared on, and so what retracts it.
enum MatchTarget {
    /// The registry of faces: the listener is a [`MatchId`] of its SSOT.
    Registry {
        shared: Arc<SharedSession>,
        id: MatchId,
    },
    /// A node: the watch is held by the node's own face, which the listener holds counted so that
    /// the watch can be ended after the session handle has been let go of.
    #[cfg(feature = "router-node")]
    Node {
        node: Arc<wz_capi_core::drive::RouterState>,
        id: u64,
    },
}

impl Drop for MatchTarget {
    fn drop(&mut self) {
        match self {
            Self::Registry { shared, id } => shared.undeclare_matching_listener(*id),
            #[cfg(feature = "router-node")]
            Self::Node { node, id } => node.unwatch_matching(*id),
        }
    }
}

impl MatchingHold {
    /// Record a live listener so it is retired with its publisher.
    pub(crate) fn new(shared: Arc<SharedSession>, id: MatchId) -> Self {
        Self {
            _target: MatchTarget::Registry { shared, id },
        }
    }

    /// Record a watch of a node so it is retired with its publisher or querier.
    #[cfg(feature = "router-node")]
    pub(crate) fn node(node: Arc<wz_capi_core::drive::RouterState>, id: u64) -> Self {
        Self {
            _target: MatchTarget::Node { node, id },
        }
    }
}

/// The ids the interests of a node's publishers and queriers are held under on its data plane:
/// one counter for the process, since an id only has to differ from the others of its node.
#[cfg(feature = "router-node")]
pub(crate) fn next_interest_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Watch whether anything of `plane` matches `key` as the session of `node`, and tell `sink` now
/// and each time that changes. The id answered ends the watch.
#[cfg(feature = "router-node")]
fn watch_on_node(
    node: &wz_capi_core::drive::RouterState,
    plane: wz_runtime_tokio::router_forward::MatchPlane,
    key: &str,
    sink: Arc<dyn Fn(bool) + Send + Sync>,
) -> u64 {
    node.watch_matching(
        plane,
        key,
        wz_runtime_tokio::locality::Locality::Any,
        Box::new(move |matching| sink(matching)),
    )
}

/// Construct a matching-status closure from its parts (zenoh-c
/// `z_closure_matching_status`).
///
/// Argument ORDER is `(this_, call, drop, context)`, not the struct's field
/// order — the same trap the sample and zid closures carry.
///
/// # Safety
/// `this_` must be valid and writable; `call` / `drop` must be null or valid C
/// function pointers; `context` is opaque to wz.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status(
    this_: *mut z_owned_closure_matching_status_t,
    call: z_closure_matching_status_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = z_owned_closure_matching_status_t {
                context,
                call,
                drop,
            }
        };
    });
}

/// Drop a matching-status closure that was never declared (zenoh-c
/// `z_closure_matching_status_drop`).
///
/// # Safety
/// `closure_` must be null or a valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_drop(
    closure_: *mut z_moved_closure_matching_status_t,
) {
    let _ = guarded(|| {
        if closure_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*closure_)._this };
        let taken = std::mem::replace(owned, z_owned_closure_matching_status_t::null_value());
        if let Some(dropfn) = taken.drop {
            let ctx = taken.context;
            // SAFETY: upstream's contract — drop runs once, and an unwind across
            // the C boundary is UB, so it is caught.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                dropfn(ctx);
            }));
        }
        Z_OK
    });
}

/// Declare a background matching listener on a publisher (zenoh-c
/// `z_publisher_declare_background_matching_listener`). Consumes the moved
/// closure on every path.
///
/// # Safety
/// `publisher` must be null or a valid loaned publisher; `callback` must be a
/// valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_declare_background_matching_listener(
    publisher: *const z_loaned_publisher_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // Consume the moved closure FIRST (consume-on-all-paths).
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let cclosure = CMatchClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_matching_status_t::null_value();

        // SAFETY: the caller's contract.
        let Some(held) = (unsafe { crate::publisher::publisher_handle(publisher) }) else {
            return Z_ENULL;
        };
        let sink = matching_sink(Arc::new(cclosure));
        match held {
            crate::publisher::PublisherHandle::Registry(state) => {
                let id = state
                    .shared
                    .declare_matching_listener(state.keyexpr.keyexpr.clone(), sink);
                state.attach_matching(MatchingHold::new(state.shared.clone(), id));
            }
            // A node's own face is told whether anything of the subscribers matches the key.
            #[cfg(feature = "router-node")]
            crate::publisher::PublisherHandle::Node(node) => {
                let id = watch_on_node(
                    node.node(),
                    wz_runtime_tokio::router_forward::MatchPlane::Subscribers,
                    node.key(),
                    sink,
                );
                node.attach_matching(MatchingHold::node(Arc::clone(node.node()), id));
            }
        }
        Z_OK
    })
}

// --- R311y564: the OWNED matching-listener family ---------------------------

/// Behind a `z_owned_matching_listener_t` handle: the listener's id and the
/// session that owns the watch.
///
/// The retraction lives in this state's `Drop`, so
/// [`z_matching_listener_drop`] and [`z_undeclare_matching_listener`] take the
/// identical path and cannot drift — the same discipline
/// [`MatchingHold`] uses for the background form.
struct ListenerState {
    _target: MatchTarget,
}

/// Owned matching listener (zenoh-c `z_owned_matching_listener_t`) — 24 bytes
/// at align 8, MEASURED by a C probe against the installed header.
#[repr(C)]
pub struct z_owned_matching_listener_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; 16],
}

/// Moved matching listener.
#[repr(C)]
pub struct z_moved_matching_listener_t {
    pub(crate) _this: z_owned_matching_listener_t,
}

impl z_owned_matching_listener_t {
    /// The gravestone value.
    #[inline]
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [0u8; 16],
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<z_owned_matching_listener_t>() == 24);
    assert!(std::mem::align_of::<z_owned_matching_listener_t>() == 8);
    assert!(std::mem::size_of::<z_moved_matching_listener_t>() == 24);
};

/// Adopt a moved closure into the aggregated sink both declare paths install.
///
/// # Safety
/// `callback` must be a valid, writable moved closure.
unsafe fn adopt_matching_closure(
    callback: *mut z_moved_closure_matching_status_t,
) -> Arc<CMatchClosure> {
    // SAFETY: the caller's contract.
    let owned = unsafe { &mut (*callback)._this };
    let cclosure = CMatchClosure::new(owned.context, owned.call, owned.drop);
    *owned = z_owned_closure_matching_status_t::null_value();
    Arc::new(cclosure)
}

/// The `MatchingSink` that forwards an aggregated verdict to a C closure.
fn matching_sink(closure: Arc<CMatchClosure>) -> Arc<dyn Fn(bool) + Send + Sync> {
    Arc::new(move |matching: bool| {
        let Some(call) = closure.call else {
            return;
        };
        let status = z_matching_status_t { matching };
        let ctx = closure.context.0;
        // SAFETY: `call` is the C callback and `status` outlives it. An unwind
        // out of the callback across `extern "C"` is UB, so it is caught.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            call(&status, ctx);
        }));
    })
}

/// Install a declared listener into the caller's owned slot.
///
/// # Safety
/// `out` must be valid and writable.
unsafe fn install_listener(out: *mut z_owned_matching_listener_t, target: MatchTarget) {
    let boxed = Box::into_raw(Box::new(ListenerState { _target: target })) as *mut c_void;
    // SAFETY: the caller's contract.
    unsafe {
        *out = z_owned_matching_listener_t {
            handle: boxed,
            _pad: [0u8; 16],
        }
    };
}

/// Declare an OWNED matching listener on a publisher (zenoh-c
/// `z_publisher_declare_matching_listener`). Consumes the moved closure on
/// every path.
///
/// # Safety
/// `publisher` must be null or a valid loaned publisher; `matching_listener`
/// must be valid and writable; `callback` must be a valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_declare_matching_listener(
    publisher: *const z_loaned_publisher_t,
    matching_listener: *mut z_owned_matching_listener_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() || matching_listener.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *matching_listener = z_owned_matching_listener_t::null_value() };
        // Consume the moved closure FIRST (consume-on-all-paths).
        // SAFETY: as above.
        let closure = unsafe { adopt_matching_closure(callback) };
        // SAFETY: as above.
        let Some(held) = (unsafe { crate::publisher::publisher_handle(publisher) }) else {
            return Z_ENULL;
        };
        let target = match held {
            crate::publisher::PublisherHandle::Registry(state) => MatchTarget::Registry {
                shared: state.shared.clone(),
                id: state.shared.declare_matching_listener(
                    state.keyexpr.keyexpr.clone(),
                    matching_sink(closure),
                ),
            },
            #[cfg(feature = "router-node")]
            crate::publisher::PublisherHandle::Node(node) => MatchTarget::Node {
                node: Arc::clone(node.node()),
                id: watch_on_node(
                    node.node(),
                    wz_runtime_tokio::router_forward::MatchPlane::Subscribers,
                    node.key(),
                    matching_sink(closure),
                ),
            },
        };
        // SAFETY: the slot was gravestoned above.
        unsafe { install_listener(matching_listener, target) };
        Z_OK
    })
}

// --- R311y568: the ADVANCED publisher's matching trio ------------------------
//
// The same three entry points the base publisher has, on a handle whose state is
// `crate::advanced`'s. They route through the SAME
// `SharedSession::declare_matching_listener` / `has_matching` the base plane
// uses, keyed by the advanced publisher's own declared keyexpr — so the two
// planes cannot report different verdicts for the same keyexpr.
//
// UNSTABLE-gated, and the gate is FORCED rather than chosen: upstream declares
// the whole `ze_advanced_*` plane under `#if defined(Z_FEATURE_UNSTABLE_API)`,
// so `crate::advanced` is not compiled on the other arm and these three name a
// type that does not exist there. That is the y536 rule read forwards — a
// helper's cfg is the OR of every arm that calls it — and Layer C1cc caught this
// one on its first run, because it clippies the arm the local build was not.

/// Declare an OWNED matching listener on an ADVANCED publisher (zenoh-c
/// `ze_advanced_publisher_declare_matching_listener`).
///
/// # Safety
/// `publisher` must be null or a valid loaned advanced publisher;
/// `matching_listener` must be valid and writable; `callback` must be a valid
/// moved closure, which is consumed on every path.
#[cfg(all(feature = "advanced", not(feature = "zenoh-c-no-unstable-api")))]
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_declare_matching_listener(
    publisher: *const crate::advanced::ze_loaned_advanced_publisher_t,
    matching_listener: *mut z_owned_matching_listener_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() || matching_listener.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *matching_listener = z_owned_matching_listener_t::null_value() };
        // Consume the moved closure FIRST (consume-on-all-paths).
        // SAFETY: as above.
        let closure = unsafe { adopt_matching_closure(callback) };
        // SAFETY: as above.
        let Some((shared, keyexpr)) =
            (unsafe { crate::advanced::adv_pub_shared_and_keyexpr(publisher) })
        else {
            return Z_ENULL;
        };
        let id = shared.declare_matching_listener(keyexpr, matching_sink(closure));
        // SAFETY: the slot was gravestoned above.
        unsafe { install_listener(matching_listener, MatchTarget::Registry { shared, id }) };
        Z_OK
    })
}

/// Declare a BACKGROUND matching listener on an ADVANCED publisher (zenoh-c
/// `ze_advanced_publisher_declare_background_matching_listener`).
///
/// Declares into a LOCAL owned handle and discards it, the same construction the
/// background declares elsewhere use — so the listener is retired when the
/// publisher is, through [`MatchingHold`]'s `Drop`, and nothing can undeclare it
/// sooner.
///
/// # Safety
/// `publisher` must be null or a valid loaned advanced publisher; `callback` must
/// be a valid moved closure, which is consumed on every path.
#[cfg(all(feature = "advanced", not(feature = "zenoh-c-no-unstable-api")))]
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_declare_background_matching_listener(
    publisher: *const crate::advanced::ze_loaned_advanced_publisher_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    let mut sink = z_owned_matching_listener_t::null_value();
    // SAFETY: the caller's contract, delegated.
    unsafe { ze_advanced_publisher_declare_matching_listener(publisher, &mut sink, callback) }
}

/// Poll an ADVANCED publisher's matching status (zenoh-c
/// `ze_advanced_publisher_get_matching_status`).
///
/// # Safety
/// `this_` must be null or a valid loaned advanced publisher; `matching_status`
/// must be valid and writable.
#[cfg(all(feature = "advanced", not(feature = "zenoh-c-no-unstable-api")))]
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_get_matching_status(
    this_: *const crate::advanced::ze_loaned_advanced_publisher_t,
    matching_status: *mut z_matching_status_t,
) -> ZResult {
    guarded(|| {
        if matching_status.is_null() {
            return Z_ENULL;
        }
        // Written before any fallible work, so a caller that ignores the code
        // reads `false` rather than a stale value.
        // SAFETY: the caller's contract.
        unsafe { (*matching_status).matching = false };
        // SAFETY: as above.
        let Some((shared, keyexpr)) =
            (unsafe { crate::advanced::adv_pub_shared_and_keyexpr(this_) })
        else {
            return Z_ENULL;
        };
        // SAFETY: as above.
        unsafe { (*matching_status).matching = shared.has_matching(&keyexpr) };
        Z_OK
    })
}

/// Declare an OWNED matching listener on a querier (zenoh-c
/// `z_querier_declare_matching_listener`).
///
/// The querier's verdict is about QUERYABLES, not subscribers — a different
/// scope over the same aggregation, which is why it routes through
/// `declare_matching_listener_queryable` rather than the publisher's path.
///
/// # Safety
/// `querier` must be null or a valid loaned querier; `matching_listener` must
/// be valid and writable; `callback` must be a valid moved closure.
#[cfg(feature = "query")]
#[no_mangle]
pub unsafe extern "C" fn z_querier_declare_matching_listener(
    querier: *const crate::abi::z_loaned_querier_t,
    matching_listener: *mut z_owned_matching_listener_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() || matching_listener.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *matching_listener = z_owned_matching_listener_t::null_value() };
        // SAFETY: as above.
        let closure = unsafe { adopt_matching_closure(callback) };
        // SAFETY: as above.
        let Some(held) = (unsafe { crate::querier::querier_handle(querier) }) else {
            return Z_ENULL;
        };
        let target = match held {
            crate::querier::QuerierHandle::Registry(state) => MatchTarget::Registry {
                shared: state.shared.clone(),
                id: state.shared.declare_querier_matching_listener(
                    state.keyexpr.literal().to_owned(),
                    matching_sink(closure),
                    state.matching_needs_complete(),
                ),
            },
            #[cfg(feature = "router-node")]
            crate::querier::QuerierHandle::Node(node) => MatchTarget::Node {
                node: Arc::clone(node.node()),
                id: watch_on_node(
                    node.node(),
                    node.plane(),
                    node.key(),
                    matching_sink(closure),
                ),
            },
        };
        // SAFETY: the slot was gravestoned above.
        unsafe { install_listener(matching_listener, target) };
        Z_OK
    })
}

/// Poll a publisher's matching verdict (zenoh-c
/// `z_publisher_get_matching_status`).
///
/// Computed FRESH across faces rather than read off a listener's cached state,
/// so it answers correctly for a publisher that never declared one.
///
/// # Safety
/// `this_` must be null or a valid loaned publisher; `matching_status` must be
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_get_matching_status(
    this_: *const z_loaned_publisher_t,
    matching_status: *mut z_matching_status_t,
) -> ZResult {
    guarded(|| {
        if matching_status.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract — written before any fallible work so a
        // caller that ignores the code reads `false` rather than a stale value.
        unsafe { (*matching_status).matching = false };
        // SAFETY: as above.
        let Some(held) = (unsafe { crate::publisher::publisher_handle(this_) }) else {
            return Z_ENULL;
        };
        let matching = match held {
            crate::publisher::PublisherHandle::Registry(state) => {
                state.shared.has_matching(&state.keyexpr.keyexpr)
            }
            #[cfg(feature = "router-node")]
            crate::publisher::PublisherHandle::Node(node) => node.node().matching_status(
                wz_runtime_tokio::router_forward::MatchPlane::Subscribers,
                node.key(),
                wz_runtime_tokio::locality::Locality::Any,
            ),
        };
        // SAFETY: as above.
        unsafe { (*matching_status).matching = matching };
        Z_OK
    })
}

/// Poll a querier's matching verdict (zenoh-c `z_querier_get_matching_status`).
///
/// # Safety
/// `this_` must be null or a valid loaned querier; `matching_status` must be
/// valid and writable.
#[cfg(feature = "query")]
#[no_mangle]
pub unsafe extern "C" fn z_querier_get_matching_status(
    this_: *const crate::abi::z_loaned_querier_t,
    matching_status: *mut z_matching_status_t,
) -> ZResult {
    guarded(|| {
        if matching_status.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { (*matching_status).matching = false };
        // SAFETY: as above.
        let Some(held) = (unsafe { crate::querier::querier_handle(this_) }) else {
            return Z_ENULL;
        };
        let matching = match held {
            crate::querier::QuerierHandle::Registry(state) => state
                .shared
                .has_matching_queryable(state.keyexpr.literal(), state.matching_needs_complete()),
            #[cfg(feature = "router-node")]
            crate::querier::QuerierHandle::Node(node) => node.node().matching_status(
                node.plane(),
                node.key(),
                wz_runtime_tokio::locality::Locality::Any,
            ),
        };
        // SAFETY: as above.
        unsafe { (*matching_status).matching = matching };
        Z_OK
    })
}

/// Retract a matching listener (zenoh-c `z_undeclare_matching_listener`).
///
/// # Safety
/// `this_` must be null or a valid, writable moved matching listener.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_matching_listener(
    this_: *mut z_moved_matching_listener_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated — the drop path IS the
        // retraction, so the explicit and implicit forms cannot drift.
        unsafe { z_matching_listener_drop(this_) };
        Z_OK
    })
}

/// Drop a matching listener (zenoh-c `z_matching_listener_drop`), retracting
/// its watch.
///
/// # Safety
/// `this_` must be null or a valid, writable moved matching listener.
#[no_mangle]
pub unsafe extern "C" fn z_matching_listener_drop(this_: *mut z_moved_matching_listener_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        unsafe { (*this_)._this = z_owned_matching_listener_t::null_value() };
        if !handle.is_null() {
            // SAFETY: every listener handle is a `Box::into_raw`; the `Drop`
            // impl retracts the watch.
            drop(unsafe { Box::from_raw(handle as *mut ListenerState) });
        }
    });
}

/// `true` iff the owned listener is live (zenoh-c
/// `z_internal_matching_listener_check`).
///
/// # Safety
/// `this_` must be null or a valid owned matching listener.
#[no_mangle]
pub unsafe extern "C" fn z_internal_matching_listener_check(
    this_: *const z_owned_matching_listener_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Gravestone an owned matching listener (zenoh-c
/// `z_internal_matching_listener_null`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_matching_listener_null(
    this_: *mut z_owned_matching_listener_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_matching_listener_t::null_value() };
    }
}

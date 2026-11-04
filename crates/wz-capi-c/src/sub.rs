// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The subscriber plane: the sample closure the C side builds, and the
//! declaration it hands that closure to.
//!
//! ## One C subscription is N wz subscribers
//!
//! A zenoh-c session is "one session, many peers"; a wz unicast `Session` is
//! exactly one peer. [`wz_capi_core`] resolves that with a face
//! registry and a declaration SSOT replayed onto each face as it comes up, so a
//! `z_declare_subscriber` before any peer is connected still records the
//! subscription and every FUTURE face gets it. That is upstream's
//! declare-before-peer behaviour and it is shared with the zenoh-pico ABI rather
//! than re-derived here.
//!
//! Because the fan-out is per face, the closure is handed in as a FACTORY: the
//! registry mints one wz callback per face, all sharing one `Arc<CClosure>`, and
//! the C `drop(context)` runs when the last of them is released.
//!
//! ## Consume-on-all-paths
//!
//! `z_declare_subscriber` takes a `z_moved_closure_sample_t*`. Upstream consumes
//! it whether or not the declaration succeeds, so the closure is adopted FIRST
//! here and the source nulled immediately: an early error return then drops the
//! adopted value, which runs the C `drop(context)` exactly once. Reading the
//! session first and returning early would leak the caller's context on that
//! path — a divergence visible only as a leak in their code, not ours.

use std::ffi::c_void;
use std::sync::Arc;

use wz_runtime_tokio::sink::SampleView;

use crate::abi::{
    z_closure_drop_callback_t, z_closure_sample_callback_t, z_loaned_keyexpr_t, z_loaned_session_t,
    z_loaned_subscriber_t, z_moved_closure_sample_t, z_moved_subscriber_t,
    z_owned_closure_sample_t, z_owned_subscriber_t, Handle,
};
use crate::ffi::{guard_val, guarded, CClosure as FfiClosure};
use crate::keyexpr::keyexpr_str;
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::sample::MarshalCache;
use crate::session::{session_handle, SessionHandle};

use wz_capi_core::faces::{SharedSession, SubId};

/// The Rust-side wrapper a subscription's per-face callbacks share.
pub(crate) type CClosure = FfiClosure<z_closure_sample_callback_t>;

// SAFETY: sharing one subscription's `CClosure` across per-face callbacks
// requires `Sync`, so that `Arc<CClosure>` — and therefore each callback — is
// `Send`. Written for this concrete instantiation rather than blanket, because
// the argument is specific to the subscriber plane:
//
// The wrapper only READS its fields (`call`, `context`) and calls through them;
// it holds no state a second thread could tear. What the C function does with
// `context` is the C program's, and zenoh-c's own closure types carry the same
// `unsafe impl Send` and `Sync` with no promise about which thread calls them.
//
// R3069 -- THE PREMISE THIS COMMENT USED TO STATE WAS WZ'S, NOT UPSTREAM'S, and
// it is withdrawn for this ABI. It said `call` is only ever invoked from the
// session's single drive task, and R311y554 held that true by staging every local
// delivery for the drive task (`LocalDeliveryDrain::DriveTask`). Measured on the
// real library, zenoh-c runs a delivery a session makes to itself INSIDE the call
// that causes it, on the calling thread: a put's subscriber, a get's queryable and
// its reply, and a put made from inside a callback all complete before the call
// returns. So `call` runs on the thread that made the put as well as on the drive
// thread for what a peer sends, as it does on the real library, and a C program
// written for zenoh-c already tolerates both. This ABI's open chooses
// `LocalDeliveryDrain::Caller` for the local plane
// (`crate::session::open_session`); zenoh-pico's keeps `DriveTask`, because its
// callbacks are an executor's.
//
// `drop` runs only when the last `Arc` is released, which cannot overlap a live
// `call` because a running callback holds a reference.
unsafe impl Sync for CClosure {}

/// Build the wz-side subscriber callback for ONE face from a shared C closure.
///
/// The borrowed sample is valid only for the duration of the call, which is
/// zenoh-c's contract and why the C side must copy anything it keeps.
pub(crate) fn make_subscriber_callback(
    closure: Arc<CClosure>,
) -> impl FnMut(&dyn SampleView) + Send + 'static {
    // The marshal the callback hands the C side is kept from one sample to the next and
    // rewritten in place: a stream's every message would otherwise build a whole marshal
    // (a keyexpr string, a boundary list, the views over them) and drop it again.
    let mut kept = MarshalCache::new();
    move |view: &dyn SampleView| {
        let Some(call) = closure.call else {
            return;
        };
        let ctx = closure.context.0;
        kept.with_view(view, |sample| {
            // SAFETY: `call` is the C callback and `sample` is valid for exactly
            // this call. A panic unwinding OUT of the C callback across this
            // `extern "C"` boundary is UB and would tear down the drive thread,
            // so it is caught here — the drive loop survives a misbehaving
            // callback rather than taking the session with it.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                call(sample, ctx);
            }));
        });
    }
}

/// Behind a `z_owned_subscriber_t` handle: the C subscription's id in the
/// session's SSOT.
///
/// Dropping it retracts the subscription — removed from the SSOT so no future
/// face replays it, and every live face's wz subscriber dropped, which emits
/// each wire undeclare and releases the last closure reference (→ the C
/// `drop(context)`).
struct SubscriberState {
    holder: SubscriberHolder,
    /// R311y568 — the keyexpr this subscription was declared under, so
    /// [`z_subscriber_keyexpr`] can answer.
    keyexpr: crate::keyexpr::DeclaredKeyexpr,
}

/// What a subscription is declared on, and so what retracts it.
enum SubscriberHolder {
    /// The registry of faces: the subscription is a [`SubId`] of its SSOT.
    Registry {
        shared: Arc<SharedSession>,
        id: SubId,
    },
    /// A node: the subscription is hosted on its data plane, which it holds counted so that the
    /// subscription can be withdrawn after the session handle has been let go of.
    #[cfg(feature = "router-node")]
    Node {
        forwarder: Arc<wz_runtime_tokio::router_forward::RouterForwarder>,
        /// Held for [`z_subscriber_id`], its one reader, and so only where that door is.
        #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
        zid: [u8; 16],
        id: u64,
    },
    /// A liveliness subscription of a node: the node's own face is told the tokens of the other
    /// faces, and the subscription is withdrawn there. It holds the node counted, as the above
    /// holds the data plane.
    #[cfg(feature = "router-node")]
    NodeLiveliness {
        node: Arc<wz_capi_core::drive::RouterState>,
        id: u64,
    },
}

impl SubscriberHolder {
    /// The identity of the session the subscription is declared on: the entity id
    /// [`z_subscriber_id`] reports, which a build without the unstable API does not have.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    fn zid(&self) -> [u8; 16] {
        match self {
            Self::Registry { shared, .. } => shared.zid(),
            #[cfg(feature = "router-node")]
            Self::Node { zid, .. } => *zid,
            #[cfg(feature = "router-node")]
            Self::NodeLiveliness { node, .. } => crate::zid::z_id_t::from_wire(node.zid()).id,
        }
    }
}

/// Leak a [`SubscriberState`] and hand back the handle a `z_owned_subscriber_t`
/// carries.
///
/// Shared with the LIVELINESS plane rather than duplicated there, and that is not
/// tidiness: `z_liveliness_declare_subscriber` hands the C side back the SAME
/// `z_owned_subscriber_t`, so both kinds must be undeclarable through the one
/// `z_undeclare_subscriber` below. One state type is what makes that true by
/// construction — the registry already shares [`SubId`] space between the two for
/// the same reason.
pub(crate) fn subscriber_state_handle(
    shared: &Arc<SharedSession>,
    id: SubId,
    keyexpr: String,
) -> Handle {
    state_handle(
        SubscriberHolder::Registry {
            shared: shared.clone(),
            id,
        },
        keyexpr,
    )
}

/// [`subscriber_state_handle`] for a subscription hosted on a node.
#[cfg(feature = "router-node")]
fn node_subscriber_state_handle(
    node: &wz_capi_core::drive::RouterState,
    id: u64,
    keyexpr: String,
) -> Handle {
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    let zid = {
        let mut zid = [0u8; 16];
        let wire = node.zid();
        zid[..wire.len().min(16)].copy_from_slice(&wire[..wire.len().min(16)]);
        zid
    };
    state_handle(
        SubscriberHolder::Node {
            forwarder: node.shared_forwarder(),
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            zid,
            id,
        },
        keyexpr,
    )
}

fn state_handle(holder: SubscriberHolder, keyexpr: String) -> Handle {
    let mut boxed = Box::new(SubscriberState {
        holder,
        keyexpr: crate::keyexpr::DeclaredKeyexpr::new(keyexpr),
    });
    // Bind AFTER boxing — the state is at its final address only here. See
    // `DeclaredKeyexpr::bind`.
    boxed.keyexpr.bind();
    Box::into_raw(boxed) as Handle
}

impl Drop for SubscriberState {
    fn drop(&mut self) {
        match &self.holder {
            SubscriberHolder::Registry { shared, id } => shared.undeclare_subscriber(*id),
            #[cfg(feature = "router-node")]
            SubscriberHolder::Node { forwarder, id, .. } => {
                forwarder.unhost_subscriber(*id);
            }
            #[cfg(feature = "router-node")]
            SubscriberHolder::NodeLiveliness { node, id } => node.liveliness().unsubscribe(*id),
        }
    }
}

/// [`subscriber_state_handle`] for a liveliness subscription of a node, which the liveliness
/// plane hands back as the same `z_owned_subscriber_t` so that one `z_undeclare_subscriber`
/// retracts both kinds.
#[cfg(feature = "router-node")]
pub(crate) fn node_liveliness_state_handle(
    node: &Arc<wz_capi_core::drive::RouterState>,
    id: u64,
    keyexpr: String,
) -> Handle {
    state_handle(
        SubscriberHolder::NodeLiveliness {
            node: Arc::clone(node),
            id,
        },
        keyexpr,
    )
}

/// Options for `z_declare_subscriber` (`zenoh_commons.h:464-470`).
///
/// TRANSPARENT upstream and exactly ONE field wide, which is the whole reason it
/// is declared rather than left as the `*mut c_void` this plane used until the
/// advanced subscriber needed it: `ze_advanced_subscriber_options_t` EMBEDS one
/// at offset 0, so its four bytes set every later field's offset. The pico ABI's
/// equivalent is a one-byte dummy, so the two option structs are genuinely
/// different sizes and neither may borrow the other's number.
///
/// R311y554 — the field is READ. It reaches the wz subscriber registration as
/// `SubscribeOptions::allowed_origin`, which is the predicate that decides
/// whether a loopback-origin Sample fires this subscription at all.
#[repr(C)]
pub struct z_subscriber_options_t {
    /// Restrict matching publications by their origin locality.
    pub allowed_origin: crate::publisher::zc_locality_t,
}

/// The `allowed_origin` a subscriber declaration should carry, defaulting to
/// upstream's own `z_subscriber_options_default` value when the caller passes
/// NULL (which `z_sub.c` does).
///
/// # Safety
/// `options` must be null or a valid subscriber-options struct.
unsafe fn subscriber_allowed_origin(
    options: *const z_subscriber_options_t,
) -> wz_runtime_tokio::locality::Locality {
    if options.is_null() {
        return wz_runtime_tokio::locality::Locality::Any;
    }
    // SAFETY: the caller's contract.
    crate::put::locality_from_c(unsafe { (*options).allowed_origin })
}

/// Fill in the default subscriber options (zenoh-c
/// `z_subscriber_options_default`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_options_default(this_: *mut z_subscriber_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_subscriber_options_t {
            allowed_origin: crate::publisher::ZC_LOCALITY_ANY,
        }
    };
}

/// Construct a sample closure from its parts (zenoh-c `z_closure_sample`).
///
/// The `z_closure` macro dispatches here for a `z_owned_closure_sample_t*`. Note
/// upstream's argument ORDER — `(this_, call, drop, context)` — which is not the
/// struct's field order; getting it wrong compiles and then calls the context as
/// a function.
///
/// # Safety
/// `this_` must be valid and writable. `call` / `drop` must be null or valid C
/// function pointers, and `context` is opaque to wz.
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample(
    this_: *mut z_owned_closure_sample_t,
    call: z_closure_sample_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = z_owned_closure_sample_t {
                context,
                call,
                drop,
            }
        };
    });
}

/// Drop a closure that was never declared (zenoh-c `z_closure_sample_drop`):
/// run the C `drop(context)` and null the struct.
///
/// # Safety
/// `closure_` must be null or a valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample_drop(closure_: *mut z_moved_closure_sample_t) {
    let _ = guarded(|| {
        if closure_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*closure_)._this };
        if let Some(dropfn) = owned.drop {
            let ctx = owned.context;
            // SAFETY: upstream's contract — drop runs once, and an unwind across
            // the C boundary is UB, so it is caught.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                dropfn(ctx);
            }));
        }
        *owned = z_owned_closure_sample_t::null_value();
        Z_OK
    });
}

/// Declare a subscriber (zenoh-c `z_declare_subscriber`). Consumes the moved
/// closure on every path.
///
/// # Safety
/// `session` must be a valid loaned session; `subscriber` must be valid and
/// writable; `key_expr` must be a valid loaned keyexpr; `callback` must be a
/// valid moved closure. `options` must be null or a valid subscriber-options
/// struct; R311y554 READS its one field, `allowed_origin`.
#[no_mangle]
pub unsafe extern "C" fn z_declare_subscriber(
    session: *const z_loaned_session_t,
    subscriber: *mut z_owned_subscriber_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut z_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if subscriber.is_null() || callback.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, written before any fallible work: upstream
        // specifies that on failure "subscriber will be in its gravestone state".
        unsafe { *subscriber = z_owned_subscriber_t::null_value() };

        // Consume the moved closure FIRST (see the module note on
        // consume-on-all-paths): from here the `CClosure` owns the C
        // `drop(context)` responsibility, so every early return below frees the
        // caller's context exactly as upstream does.
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let cclosure = CClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        // SAFETY: the caller's contract for both handles.
        let (Some(held), Some(ke)) = (unsafe { session_handle(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();
        // Reject a non-canonical keyexpr UP FRONT rather than recording a dead
        // SSOT entry that never matches yet reported success. This is the same
        // outbound gate wz's own `Session::declare_subscriber` applies per face,
        // hoisted so the verdict is uniform whether or not a peer is connected
        // yet — the registry declares best-effort per face, so a per-face reject
        // would otherwise be swallowed.
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_EINVAL;
        }

        // SAFETY: the caller's contract for the options struct.
        let allowed_origin = unsafe { subscriber_allowed_origin(options) };
        let declared = ke.clone();
        let closure = Arc::new(cclosure);
        let handle = match held {
            SessionHandle::Registry(state) => {
                let id = state.shared.declare_subscriber(ke, allowed_origin, {
                    Arc::new(move || Box::new(make_subscriber_callback(closure.clone())) as Box<_>)
                });
                subscriber_state_handle(&state.shared, id, declared)
            }
            // A node hosts the subscription on its data plane, which hands it what its own
            // session publishes and what arrives from its faces, as `allowed_origin` admits.
            #[cfg(feature = "router-node")]
            SessionHandle::Node(node) => {
                let id = node.forwarder().host_subscriber_from(
                    &ke,
                    allowed_origin,
                    Box::new(make_subscriber_callback(closure)),
                );
                node_subscriber_state_handle(node, id, declared)
            }
        };
        unsafe { *subscriber = z_owned_subscriber_t::from_handle(handle) };
        Z_OK
    })
}

/// Declare a subscriber the C side never holds (zenoh-c
/// `z_declare_background_subscriber`): it lives until the session is closed.
///
/// The difference from [`z_declare_subscriber`] is ownership, not behaviour.
/// There is no `z_owned_subscriber_t` to hand back, so nothing can undeclare it —
/// the registry's SSOT entry (and with it the last `Arc<CClosure>`) is released
/// when the session drops, which is exactly upstream's "background" contract.
///
/// Implemented by declaring into a LOCAL owned handle and discarding it, rather
/// than by a second registry path: a background subscription is an ordinary one
/// whose handle was thrown away, and giving it its own path is how the two would
/// drift.
///
/// Discarding the local is a genuine leak and that is the intent, not an
/// oversight to be papered over with `mem::forget`. `z_owned_subscriber_t` is a
/// plain `#[repr(C)]` struct with NO `Drop` — the retraction lives in the boxed
/// `SubscriberState` behind its handle, and only [`z_undeclare_subscriber`]
/// reclaims that. With no handle in the C side's hands, nobody can call it, so
/// the subscription lives until the session's registry is torn down. `mem::forget`
/// here would be a no-op that merely LOOKED load-bearing.
///
/// # Safety
/// `session` must be a valid loaned session; `key_expr` must be a valid loaned
/// keyexpr; `callback` must be a valid moved closure. `options` is accepted for
/// ABI compatibility and ignored, as for [`z_declare_subscriber`].
#[no_mangle]
pub unsafe extern "C" fn z_declare_background_subscriber(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut z_subscriber_options_t,
) -> ZResult {
    let mut sink = z_owned_subscriber_t::null_value();
    // SAFETY: the caller's contract, delegated — the local sink absorbs the
    // handle the owned form would have written out, and then goes out of scope
    // without reclaiming it. See the doc note.
    unsafe { z_declare_subscriber(session, &mut sink, key_expr, callback, options) }
}

/// This subscriber's GLOBAL ENTITY ID (zenoh-c `z_subscriber_id`).
///
/// R311y568. UNSTABLE-gated as upstream gates it, and it has to be:
/// `z_entity_global_id_t` lives in [`crate::advanced`], which is not compiled on
/// the other arm. Built through the shared
/// [`for_entity`](crate::entity::z_entity_global_id_t::for_entity)
/// constructor, so the zid / eid convention is stated once for all five
/// entity-id accessors.
///
/// # Safety
/// `subscriber` must be null or a valid loaned subscriber.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_id(
    subscriber: *const crate::abi::z_loaned_subscriber_t,
) -> crate::entity::z_entity_global_id_t {
    crate::ffi::guard_val(crate::entity::z_entity_global_id_t::empty(), || {
        if subscriber.is_null() {
            return crate::entity::z_entity_global_id_t::empty();
        }
        // SAFETY: the caller's contract — a live `Box<SubscriberState>`.
        let handle = unsafe { (*subscriber).handle };
        if handle.is_null() {
            return crate::entity::z_entity_global_id_t::empty();
        }
        // SAFETY: as above.
        let state = unsafe { &*(handle as *const SubscriberState) };
        crate::entity::z_entity_global_id_t::for_entity_of(
            state.holder.zid(),
            subscriber as *const std::ffi::c_void,
        )
    })
}

/// The keyexpr a subscriber was declared under (zenoh-c `z_subscriber_keyexpr`).
///
/// R311y568. The borrow is valid for as long as the subscriber is — the state is
/// boxed and the view is aimed at its own field.
///
/// Serves the LIVELINESS subscriber too, because both kinds share one
/// `SubscriberState` (see `subscriber_state_handle` for why), so
/// `z_liveliness_declare_subscriber`'s handle answers here as well.
///
/// # Safety
/// `subscriber` must be null or a valid loaned subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_keyexpr(
    subscriber: *const crate::abi::z_loaned_subscriber_t,
) -> *const z_loaned_keyexpr_t {
    crate::ffi::guard_val(std::ptr::null(), || {
        if subscriber.is_null() {
            return std::ptr::null();
        }
        // SAFETY: the caller's contract — the handle is a live
        // `Box<SubscriberState>` this crate leaked.
        let handle = unsafe { (*subscriber).handle };
        if handle.is_null() {
            return std::ptr::null();
        }
        // SAFETY: as above.
        unsafe { &*(handle as *const SubscriberState) }
            .keyexpr
            .as_loaned()
    })
}

/// Undeclare a subscriber (zenoh-c `z_undeclare_subscriber`): drops the wz
/// subscribers (each emitting its wire undeclare) and the callback (→ the C
/// `drop(context)`).
///
/// # Safety
/// `this_` must be null or a valid moved subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_subscriber(this_: *mut z_moved_subscriber_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<SubscriberState>` this crate leaked; its `Drop`
            // retracts the subscription.
            drop(unsafe { Box::from_raw(handle as *mut SubscriberState) });
            unsafe { (*this_)._this = z_owned_subscriber_t::null_value() };
        }
        Z_OK
    })
}

/// Drop a subscriber (zenoh-c `z_subscriber_drop`) — what `z_drop(z_move(sub))`
/// dispatches to. Identical to [`z_undeclare_subscriber`] but returns nothing,
/// which is upstream's split.
///
/// # Safety
/// `this_` must be null or a valid moved subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_drop(this_: *mut z_moved_subscriber_t) {
    // SAFETY: the caller's contract, delegated — the slot is nulled there, so a
    // double drop is a no-op.
    let _ = unsafe { z_undeclare_subscriber(this_) };
}

/// Borrow a subscriber (zenoh-c `z_subscriber_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_loan(
    this_: *const z_owned_subscriber_t,
) -> *const z_loaned_subscriber_t {
    this_ as *const z_loaned_subscriber_t
}

/// `true` iff the owned subscriber holds a live handle (zenoh-c
/// `z_internal_subscriber_check`).
///
/// # Safety
/// `this_` must be null or a valid owned subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_internal_subscriber_check(this_: *const z_owned_subscriber_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned subscriber (zenoh-c `z_internal_subscriber_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_internal_subscriber_null(this_: *mut z_owned_subscriber_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_subscriber_t::null_value() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_runtime_tokio::locality::Locality;

    /// R311y554 — `z_subscriber_options_t`'s ONE field is read.
    ///
    /// It reaches `SubscribeOptions::allowed_origin`, the predicate that
    /// decides whether a loopback-origin Sample fires this subscription. Until
    /// this round the struct was declared purely so
    /// `ze_advanced_subscriber_options_t` — which embeds one at offset 0 — had
    /// the right size, and the field itself was carried and dropped.
    ///
    /// NULL resolves to upstream's own default (`ZC_LOCALITY_ANY`), which is
    /// what `z_sub.c` passes and therefore the value that decides whether the
    /// stock example can see its own session's put.
    #[test]
    fn subscriber_options_allowed_origin_is_read_on_every_value() {
        // SAFETY: null is the documented "use defaults" input.
        assert_eq!(
            unsafe { subscriber_allowed_origin(std::ptr::null()) },
            Locality::Any,
            "z_subscriber_options_default writes ZC_LOCALITY_ANY",
        );
        for (c_value, expected) in [
            (crate::publisher::ZC_LOCALITY_ANY, Locality::Any),
            (
                crate::publisher::ZC_LOCALITY_SESSION_LOCAL,
                Locality::SessionLocal,
            ),
            (crate::publisher::ZC_LOCALITY_REMOTE, Locality::Remote),
        ] {
            let o = z_subscriber_options_t {
                allowed_origin: c_value,
            };
            // SAFETY: a live local.
            assert_eq!(
                unsafe { subscriber_allowed_origin(&o) },
                expected,
                "z_subscriber_options_t.allowed_origin = {c_value} -> {expected:?}",
            );
        }
    }
}

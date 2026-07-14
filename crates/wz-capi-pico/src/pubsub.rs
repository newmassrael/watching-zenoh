// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Publisher, subscriber, sample-closure, `z_put`, and the sample accessors.
//!
//! A pico session holds a SET of peers, so every operation here fans over the
//! session's face registry (the `faces` module) rather than binding one wz
//! session: a `connect` session has exactly one face, a `listen` session up to
//! N.
//!
//! - **publisher** (`z_declare_publisher` / `z_publisher_put` /
//!   `z_undeclare_publisher`): a keyexpr bound to the session's registry; a put
//!   calls the sync `Session::publish` on every connected face. wz has no RAII
//!   `Publisher` type, so a publisher is exactly that binding (pico's publisher
//!   is likewise a keyexpr + session with put options).
//! - **subscriber** (`z_closure_sample` + `z_declare_subscriber` /
//!   `z_undeclare_subscriber`): the C closure `{ context, call, drop }` is
//!   recorded in the session's subscription SSOT and wrapped — once per face —
//!   in a `FnMut(&dyn SampleView)` handed to that face's
//!   `Session::declare_subscriber`, so one C subscriber sees samples from every
//!   peer. On each delivery it marshals the view into a borrowed
//!   `z_loaned_sample_t` and invokes `call`. The C `drop(context)` runs once,
//!   when the subscription is undeclared and the last face's callback has
//!   released the shared closure.
//! - **sample accessors** (`z_sample_keyexpr` / `z_sample_payload`): the
//!   marshaled sample is opaque to the C code — it only borrows it (valid for
//!   the duration of `call`) and reads the keyexpr / payload back out.

use std::ffi::c_void;
use std::sync::Arc;

use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::sample::SampleKind;
use wz_runtime_tokio::session::PublishOptions;
use wz_runtime_tokio::sink::SampleView;
use wz_runtime_tokio::Reliability;

use crate::abi::{
    handle_ref, impl_handle_ownership7, z_loaned_bytes_t, z_loaned_keyexpr_t, z_moved_bytes_t,
    z_owned_bytes_t,
};
use crate::bytes::ByteBuf;
use crate::faces::{SharedSession, SubId};
use crate::ffi::{guarded, SendPtr};
use crate::keyexpr::keyexpr_str;
use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
use crate::session::{z_loaned_session_t, SessionState};

// --- opaque loaned sample --------------------------------------------------

/// Opaque loaned sample (pico `z_loaned_sample_t`). The C callback only ever
/// holds a pointer to it and passes it back to `z_sample_keyexpr` /
/// `z_sample_payload`, so Round 1 keeps it opaque rather than reproducing
/// pico's ~224 B concrete `_z_sample_t` layout.
#[repr(C)]
pub struct z_loaned_sample_t {
    _opaque: [u8; 0],
}

/// The owned marshal behind a borrowed `z_loaned_sample_t` during one
/// callback. Owns copies of the keyexpr + payload so they outlive the wz
/// `SampleView` borrow, and caches the two loaned views the accessors return.
struct SampleMarshal {
    keyexpr: String,
    payload: Vec<u8>,
    loaned_keyexpr: z_loaned_keyexpr_t,
    loaned_payload: z_loaned_bytes_t,
}

// --- C closure callback types ----------------------------------------------

/// pico `z_closure_sample_callback_t`: `void call(z_loaned_sample_t*, void*)`.
pub type z_closure_sample_callback_t =
    Option<unsafe extern "C" fn(*const z_loaned_sample_t, *mut c_void)>;
/// pico `z_closure_drop_callback_t`: `void drop(void*)`.
pub type z_closure_drop_callback_t = Option<unsafe extern "C" fn(*mut c_void)>;

/// Owned sample closure (pico `z_owned_closure_sample_t`, 24 B:
/// `{ context, call, drop }` in that field order).
#[repr(C)]
pub struct z_owned_closure_sample_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_sample_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Loaned sample closure (pico `z_loaned_closure_sample_t`), same layout.
#[repr(C)]
pub struct z_loaned_closure_sample_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_sample_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved sample closure (pico `z_moved_closure_sample_t`).
#[repr(C)]
pub struct z_moved_closure_sample_t {
    pub(crate) _this: z_owned_closure_sample_t,
}

impl z_owned_closure_sample_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

/// The Rust-side wrapper a subscription's callbacks share. Its `Drop` invokes
/// the C `drop(context)` exactly once, satisfying the pico teardown contract.
///
/// One C subscription fans out to one wz callback PER FACE, so this is held
/// behind an `Arc`: the C `drop(context)` runs when the last face's callback
/// and the registry's SSOT entry have both released it.
pub(crate) struct CClosure {
    context: SendPtr,
    call: z_closure_sample_callback_t,
    drop: z_closure_drop_callback_t,
}

impl Drop for CClosure {
    fn drop(&mut self) {
        if let Some(dropfn) = self.drop.take() {
            // SAFETY: pico contract — drop runs once, never concurrently with
            // call. A panic across the C boundary is UB, so guard it.
            let ctx = self.context.0;
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                dropfn(ctx);
            }));
        }
    }
}

// SAFETY: sharing one subscription's `CClosure` across a per-face callback
// requires `Sync` (for `Arc<CClosure>` — and so each callback — to be `Send`).
// Sharing `&CClosure` is sound because `call` is only ever invoked from the
// session's single drive task: every face of a session is driven on ONE task
// (the accept loop multiplexes its faces there via one `select!`; a dialed
// session has exactly one drive loop), and inbound dispatch is the ONLY caller
// of `call`. It is load-bearing that the C application thread never invokes
// `call`: the fan-out publishes are `Locality::Remote` (see `put_options`), so
// `z_put` stages NO loopback fire and never drains a callback on the C thread.
// Were the publishes local-capable, a C-thread `z_put` whose keyexpr matched a
// subscription would drain that face's loopback fire on the C thread
// concurrently with the drive thread's inbound dispatch on another face —
// two `call(context)`s at once on one C context, the exact data race the pico
// single-threaded-callback contract forbids. `drop` runs only when the last
// `Arc` is released, which cannot overlap a live `call` (a running callback
// holds a reference). That is pico's closure contract: the callback fires from
// the read task, the drop from teardown, never concurrently.
unsafe impl Sync for CClosure {}

/// Build the wz-side subscriber callback for ONE face from a shared C closure.
///
/// On each delivery it marshals the wz `SampleView` into a borrowed
/// `z_loaned_sample_t` and invokes the C `call`. The marshal (and so the
/// borrowed keyexpr / payload) is valid only for the duration of that call —
/// pico's contract, which is why the C side must copy anything it keeps.
pub(crate) fn make_subscriber_callback(
    closure: Arc<CClosure>,
) -> impl FnMut(&dyn SampleView) + Send + 'static {
    move |view: &dyn SampleView| {
        let call = match closure.call {
            Some(f) => f,
            None => return,
        };
        let keyexpr = view.keyexpr().to_owned();
        let payload = view.payload().to_vec();
        let mut marshal = SampleMarshal {
            keyexpr,
            payload,
            loaned_keyexpr: z_loaned_keyexpr_t {
                _start: std::ptr::null(),
                _len: 0,
            },
            loaned_payload: z_loaned_bytes_t {
                handle: std::ptr::null_mut(),
                _pad: [std::ptr::null_mut(); 3],
            },
        };
        marshal.loaned_keyexpr = z_loaned_keyexpr_t {
            _start: marshal.keyexpr.as_ptr(),
            _len: marshal.keyexpr.len(),
        };
        marshal.loaned_payload.handle = &marshal.payload as *const Vec<u8> as *mut c_void;
        let sample_ptr = &marshal as *const SampleMarshal as *const z_loaned_sample_t;
        // SAFETY: `call` is the C callback; `marshal` outlives the call and the
        // borrowed sample is valid only for its duration (pico contract).
        // `context` travels with the drive dispatch. A panic unwinding OUT of
        // the C callback across this `extern "C"` boundary is UB and would tear
        // down the drive thread, so it is caught here — the drive loop survives
        // a misbehaving callback.
        let ctx = closure.context.0;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            call(sample_ptr, ctx);
        }));
    }
}

// --- publisher -------------------------------------------------------------

/// Behind a `z_owned_publisher_t` handle: a keyexpr bound to the session's
/// face registry, so a put fans out to every connected peer.
struct PublisherState {
    shared: Arc<SharedSession>,
    keyexpr: String,
}

/// Owned publisher (pico `z_owned_publisher_t`). Round 1 uses a handle model;
/// the exact `Z_FEATURE`-dependent pico size-match is a follow-up audit.
#[repr(C)]
pub struct z_owned_publisher_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Loaned publisher (pico `z_loaned_publisher_t`).
#[repr(C)]
pub struct z_loaned_publisher_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Moved publisher (pico `z_moved_publisher_t`).
#[repr(C)]
pub struct z_moved_publisher_t {
    pub(crate) _this: z_owned_publisher_t,
}

impl z_owned_publisher_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 3],
        }
    }
}

// --- subscriber ------------------------------------------------------------

/// Behind a `z_owned_subscriber_t` handle: the C subscription's id in the
/// session's SSOT. Dropping it retracts the subscription — removing it from
/// the SSOT (so no future face replays it) and dropping every live face's wz
/// subscriber, which emits each wire undeclare and releases the last closure
/// reference (→ the C `drop(context)`).
struct SubscriberState {
    shared: Arc<SharedSession>,
    id: SubId,
}

impl Drop for SubscriberState {
    fn drop(&mut self) {
        self.shared.undeclare_subscriber(self.id);
    }
}

/// Owned subscriber (pico `z_owned_subscriber_t`). Handle model (see publisher).
#[repr(C)]
pub struct z_owned_subscriber_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Loaned subscriber (pico `z_loaned_subscriber_t`).
#[repr(C)]
pub struct z_loaned_subscriber_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Moved subscriber (pico `z_moved_subscriber_t`).
#[repr(C)]
pub struct z_moved_subscriber_t {
    pub(crate) _this: z_owned_subscriber_t,
}

impl z_owned_subscriber_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 3],
        }
    }
}

// --- publisher / subscriber ownership families (the pico 7-fn no-copy set) --
//
// pico exposes both `z_undeclare_*` (the RAII teardown, below) and the generic
// `z_*_drop`; either consumes the moved handle and nulls the source, so a
// defensive double-call is a safe no-op.

/// # Safety
/// `h` must be a live `Box::into_raw::<PublisherState>` pointer.
unsafe fn free_publisher(h: *mut c_void) {
    drop(Box::from_raw(h as *mut PublisherState));
}
/// # Safety
/// `h` must be a live `Box::into_raw::<SubscriberState>` pointer.
unsafe fn free_subscriber(h: *mut c_void) {
    drop(Box::from_raw(h as *mut SubscriberState));
}

impl_handle_ownership7!(
    z_owned_publisher_t,
    z_loaned_publisher_t,
    z_moved_publisher_t,
    free_publisher,
    z_internal_publisher_null,
    z_internal_publisher_check,
    z_publisher_loan,
    z_publisher_loan_mut,
    z_publisher_move,
    z_publisher_take,
    z_publisher_drop
);

impl_handle_ownership7!(
    z_owned_subscriber_t,
    z_loaned_subscriber_t,
    z_moved_subscriber_t,
    free_subscriber,
    z_internal_subscriber_null,
    z_internal_subscriber_check,
    z_subscriber_loan,
    z_subscriber_loan_mut,
    z_subscriber_move,
    z_subscriber_take,
    z_subscriber_drop
);

// --- helpers ---------------------------------------------------------------

/// Take ownership of a moved payload's bytes, nulling the source.
unsafe fn take_moved_bytes(payload: *mut z_moved_bytes_t) -> Option<Vec<u8>> {
    if payload.is_null() {
        return None;
    }
    let handle = (*payload)._this.handle;
    if handle.is_null() {
        return None;
    }
    let buf = Box::from_raw(handle as *mut ByteBuf);
    (*payload)._this = z_owned_bytes_t::null_value();
    Some(*buf)
}

/// Read the `SessionState` behind a loaned session.
unsafe fn session_state<'a>(zs: *const z_loaned_session_t) -> Option<&'a SessionState> {
    if zs.is_null() {
        return None;
    }
    let val = (*zs)._val;
    if val.is_null() {
        return None;
    }
    Some(&*(val as *const SessionState))
}

fn put_options() -> PublishOptions {
    // `Locality::Remote`, not the `Any` default. A pico session's own `z_put`
    // is delivered to its OWN local subscribers at most ONCE
    // (`_z_write` -> `_z_session_deliver_push_locally`, gated on
    // `Z_FEATURE_LOCAL_SUBSCRIBER`, `~/zenoh-pico/src/net/primitives.c:198-201`).
    // Here the C session is N per-face wz sessions, each with its own observer
    // carrying a replica of the subscription — so a local-capable publish would
    // (a) fire the one C callback ONCE PER FACE (N duplicate local deliveries
    // for a single `z_put`), and (b) drain that fire on the C thread, racing the
    // drive thread's inbound dispatch on another face (see the `CClosure` Sync
    // note). Remote-only sidesteps both: the fan-out reaches every PEER over the
    // wire, and self-delivery to local subscribers is deferred as a named
    // divergence (this crate has never implemented `Z_FEATURE_LOCAL_SUBSCRIBER`;
    // a faithful build would deliver locally exactly once, at the registry
    // level, serialized against inbound dispatch).
    let mut opts = PublishOptions::default()
        .with_reliability(Reliability::Reliable)
        .with_locality(Locality::Remote);
    opts.kind = SampleKind::Put;
    opts
}

// --- z_put -----------------------------------------------------------------

/// Publish a payload on a session (pico `z_put`). Consumes the moved payload.
#[no_mangle]
pub unsafe extern "C" fn z_put(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    payload: *mut z_moved_bytes_t,
    _options: *const c_void,
) -> ZResult {
    guarded(|| {
        // Consume the moved payload FIRST so it is freed on every path (pico's
        // "z_move consumes on all paths" contract): the owned `Vec` is dropped
        // on any early error below, and `take_moved_bytes` already nulled the
        // caller's source struct.
        let buf = match take_moved_bytes(payload) {
            Some(b) => b,
            None => return Z_ERR_NULL,
        };
        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k,
            None => return Z_ERR_INVALID,
        };
        match state.shared.publish_all(ke, &buf, &put_options()) {
            Ok(_) => Z_OK,
            Err(_) => Z_ERR_GENERIC,
        }
    })
}

// --- publisher exports -----------------------------------------------------

/// Declare a publisher (pico `z_declare_publisher`).
#[no_mangle]
pub unsafe extern "C" fn z_declare_publisher(
    zs: *const z_loaned_session_t,
    publisher: *mut z_owned_publisher_t,
    keyexpr: *const z_loaned_keyexpr_t,
    _options: *const c_void,
) -> ZResult {
    guarded(|| {
        if publisher.is_null() {
            return Z_ERR_NULL;
        }
        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        let boxed = Box::new(PublisherState {
            shared: state.shared.clone(),
            keyexpr: ke,
        });
        *publisher = z_owned_publisher_t {
            handle: Box::into_raw(boxed) as *mut c_void,
            _pad: [std::ptr::null_mut(); 3],
        };
        Z_OK
    })
}

/// Publish through a publisher (pico `z_publisher_put`). Consumes the payload.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_put(
    publisher: *const z_loaned_publisher_t,
    payload: *mut z_moved_bytes_t,
    _options: *const c_void,
) -> ZResult {
    guarded(|| {
        // Consume the moved payload first (pico consume-on-all-paths contract):
        // dropped + source nulled even if the publisher handle is invalid.
        let buf = match take_moved_bytes(payload) {
            Some(b) => b,
            None => return Z_ERR_NULL,
        };
        let state = match handle_ref::<z_loaned_publisher_t, PublisherState>(publisher) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        match state
            .shared
            .publish_all(&state.keyexpr, &buf, &put_options())
        {
            Ok(_) => Z_OK,
            Err(_) => Z_ERR_GENERIC,
        }
    })
}

/// Undeclare a publisher (pico `z_undeclare_publisher`).
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_publisher(publisher: *mut z_moved_publisher_t) -> ZResult {
    guarded(|| {
        if publisher.is_null() {
            return Z_OK;
        }
        let handle = (*publisher)._this.handle;
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut PublisherState));
            (*publisher)._this = z_owned_publisher_t::null_value();
        }
        Z_OK
    })
}

// --- closure ---------------------------------------------------------------

/// Build an owned sample closure from a callback + drop + context (pico
/// `z_closure_sample`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample(
    closure: *mut z_owned_closure_sample_t,
    call: z_closure_sample_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        if closure.is_null() {
            return Z_ERR_NULL;
        }
        *closure = z_owned_closure_sample_t {
            context,
            call,
            drop,
        };
        Z_OK
    })
}

/// Zero an owned closure (pico `z_internal_closure_sample_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_sample_null(closure: *mut z_owned_closure_sample_t) {
    if !closure.is_null() {
        *closure = z_owned_closure_sample_t::null_value();
    }
}

/// `true` iff the closure holds a callback (pico
/// `z_internal_closure_sample_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_sample_check(
    closure: *const z_owned_closure_sample_t,
) -> bool {
    !closure.is_null() && (*closure).call.is_some()
}

/// Borrow an owned closure (pico `z_closure_sample_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample_loan(
    closure: *const z_owned_closure_sample_t,
) -> *const z_loaned_closure_sample_t {
    closure as *const z_loaned_closure_sample_t
}

/// Move-cast an owned closure (pico `z_closure_sample_move`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample_move(
    closure: *mut z_owned_closure_sample_t,
) -> *mut z_moved_closure_sample_t {
    closure as *mut z_moved_closure_sample_t
}

/// Take an owned closure out of `src` into `dst` (pico
/// `z_closure_sample_take`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample_take(
    dst: *mut z_owned_closure_sample_t,
    src: *mut z_moved_closure_sample_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).context = (*src)._this.context;
    (*dst).call = (*src)._this.call;
    (*dst).drop = (*src)._this.drop;
    (*src)._this = z_owned_closure_sample_t::null_value();
}

/// Drop an owned closure without ever having declared it (pico
/// `z_closure_sample_drop`): run the C `drop(context)` and null the struct.
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample_drop(closure: *mut z_moved_closure_sample_t) {
    let _ = guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        let owned = &mut (*closure)._this;
        if let Some(dropfn) = owned.drop {
            dropfn(owned.context);
        }
        *owned = z_owned_closure_sample_t::null_value();
        Z_OK
    });
}

// --- subscriber exports ----------------------------------------------------

/// Declare a subscriber (pico `z_declare_subscriber`). Consumes the moved
/// closure.
#[no_mangle]
pub unsafe extern "C" fn z_declare_subscriber(
    zs: *const z_loaned_session_t,
    subscriber: *mut z_owned_subscriber_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    _options: *const c_void,
) -> ZResult {
    guarded(|| {
        if subscriber.is_null() || callback.is_null() {
            return Z_ERR_NULL;
        }
        // Consume the moved closure FIRST (pico consume-on-all-paths contract):
        // the `CClosure` now owns the C `drop(context)` responsibility, so an
        // early error return below drops it and frees the context; on success
        // it moves into the subscriber callback.
        let owned = &mut (*callback)._this;
        let cclosure = CClosure {
            context: SendPtr(owned.context),
            call: owned.call,
            drop: owned.drop,
        };
        *owned = z_owned_closure_sample_t::null_value();

        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };

        // Record the subscription in the session's SSOT and declare it on every
        // face that is already up. With no peer yet — a listener before its
        // first connection — this declares nothing on the wire and still
        // records the entry (pico's declare-before-peer); each face replays the
        // SSOT as it comes up. Recording the local entry always succeeds
        // (mirrors pico's `_z_register_subscriber`).
        let id = state.shared.declare_subscriber(ke, Arc::new(cclosure));
        let boxed = Box::new(SubscriberState {
            shared: state.shared.clone(),
            id,
        });
        *subscriber = z_owned_subscriber_t {
            handle: Box::into_raw(boxed) as *mut c_void,
            _pad: [std::ptr::null_mut(); 3],
        };
        Z_OK
    })
}

/// Undeclare a subscriber (pico `z_undeclare_subscriber`): drops the wz
/// subscriber (undeclare on the wire) and the callback (→ C `drop(context)`).
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_subscriber(subscriber: *mut z_moved_subscriber_t) -> ZResult {
    guarded(|| {
        if subscriber.is_null() {
            return Z_OK;
        }
        let handle = (*subscriber)._this.handle;
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut SubscriberState));
            (*subscriber)._this = z_owned_subscriber_t::null_value();
        }
        Z_OK
    })
}

// --- sample accessors ------------------------------------------------------

/// Borrow a delivered sample's keyexpr (pico `z_sample_keyexpr`).
#[no_mangle]
pub unsafe extern "C" fn z_sample_keyexpr(
    sample: *const z_loaned_sample_t,
) -> *const z_loaned_keyexpr_t {
    if sample.is_null() {
        return std::ptr::null();
    }
    let marshal = &*(sample as *const SampleMarshal);
    &marshal.loaned_keyexpr as *const z_loaned_keyexpr_t
}

/// Borrow a delivered sample's payload (pico `z_sample_payload`).
#[no_mangle]
pub unsafe extern "C" fn z_sample_payload(
    sample: *const z_loaned_sample_t,
) -> *const z_loaned_bytes_t {
    if sample.is_null() {
        return std::ptr::null();
    }
    let marshal = &*(sample as *const SampleMarshal);
    &marshal.loaned_payload as *const z_loaned_bytes_t
}

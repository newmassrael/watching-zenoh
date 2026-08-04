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

use std::ffi::{c_int, c_void};
use std::sync::{Arc, Mutex as StdMutex};

use wz_runtime_tokio::declare::LivelinessSample;
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
use crate::ffi::{guarded, CClosure as FfiClosure};
use crate::keyexpr::{keyexpr_mapping, keyexpr_str};
use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
use crate::session::{session_state, z_loaned_session_t};
use wz_capi_core::faces::{MatchId, SharedSession, SubId};

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
///
/// Shared with the reply plane: `z_reply_ok` hands back a `z_loaned_sample_t`,
/// so [`crate::get`] marshals a reply's Put/Del body into this same type rather
/// than a parallel one — the accessors below then serve both planes, which is
/// what keeps `z_sample_keyexpr` / `z_sample_payload` / `z_sample_kind` a single
/// definition instead of two that can drift.
pub(crate) struct SampleMarshal {
    keyexpr: String,
    payload: Vec<u8>,
    kind: z_sample_kind_t,
    loaned_keyexpr: z_loaned_keyexpr_t,
    loaned_payload: z_loaned_bytes_t,
}

impl SampleMarshal {
    /// Build the marshal with its cached views still UNBOUND — [`Self::bind`]
    /// must run once the value has reached its final address. See
    /// [`crate::query::QueryMarshal::bind`] for why the split is load-bearing
    /// (an earlier cut bound inside a by-value constructor and handed C a
    /// pointer into the dead constructor frame).
    pub(crate) fn new(keyexpr: String, payload: Vec<u8>, kind: z_sample_kind_t) -> Self {
        Self {
            keyexpr,
            payload,
            kind,
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
            loaned_payload: z_loaned_bytes_t {
                handle: std::ptr::null_mut(),
                _pad: [std::ptr::null_mut(); 3],
            },
        }
    }

    /// Point the cached views at this marshal's own fields. MUST run only once
    /// the marshal sits at its FINAL address.
    pub(crate) fn bind(&mut self) {
        self.loaned_keyexpr =
            z_loaned_keyexpr_t::borrowed(self.keyexpr.as_ptr(), self.keyexpr.len());
        self.loaned_payload.handle = &self.payload as *const Vec<u8> as *mut c_void;
    }

    /// This marshal viewed as the borrowed `z_loaned_sample_t` the C side gets.
    pub(crate) fn as_loaned(&self) -> *const z_loaned_sample_t {
        self as *const SampleMarshal as *const z_loaned_sample_t
    }
}

/// pico `z_sample_kind_t` (`api/constants.h:164-168`): how the sample was
/// issued. A plain C enum, so it occupies an `int`.
pub type z_sample_kind_t = c_int;
/// pico `Z_SAMPLE_KIND_PUT` = 0 (`constants.h:165`), also
/// `Z_SAMPLE_KIND_DEFAULT`.
pub const Z_SAMPLE_KIND_PUT: z_sample_kind_t = 0;
/// pico `Z_SAMPLE_KIND_DELETE` = 1 (`constants.h:166`).
pub const Z_SAMPLE_KIND_DELETE: z_sample_kind_t = 1;

/// The pico kind constant for a wz [`SampleKind`].
pub(crate) fn sample_kind_of(kind: SampleKind) -> z_sample_kind_t {
    match kind {
        SampleKind::Put => Z_SAMPLE_KIND_PUT,
        SampleKind::Del => Z_SAMPLE_KIND_DELETE,
    }
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
    pub(crate) fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

/// The Rust-side wrapper a subscription's callbacks share — the sample plane's
/// instantiation of the shared [`crate::ffi::CClosure`] mechanism (which owns
/// the `{context, call, drop}` shape and the drop-once `Drop`).
///
/// One C subscription fans out to one wz callback PER FACE, so this is held
/// behind an `Arc`: the C `drop(context)` runs when the last face's callback
/// and the registry's SSOT entry have both released it.
pub(crate) type CClosure = FfiClosure<z_closure_sample_callback_t>;

// SAFETY: sharing one subscription's `CClosure` across a per-face callback
// requires `Sync` (for `Arc<CClosure>` — and so each callback — to be `Send`).
// Written per-plane rather than blanket-implemented on the generic, because the
// argument below is specific to THIS plane (see `crate::ffi::CClosure`).
//
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
/// Marshal a wz LIVELINESS event into the borrowed `z_loaned_sample_t` a C
/// sample closure expects.
///
/// pico hands liveliness events to an ORDINARY `z_closure_sample_t`, so this is
/// the same shape as [`make_subscriber_callback`] with two differences that are
/// the whole mapping: the payload is EMPTY (a presence event carries no data)
/// and the kind carries the discriminator — a token appearing is `PUT`, one
/// going away is `DELETE`. Upstream's `z_sub_liveliness.c` switches on exactly
/// that to print "Alive"/"Dropped".
pub(crate) fn make_liveliness_callback(
    closure: Arc<CClosure>,
) -> impl FnMut(LivelinessSample<'_>) + Send + 'static {
    move |sample: LivelinessSample<'_>| {
        let call = match closure.call {
            Some(f) => f,
            None => return,
        };
        let mut marshal = SampleMarshal::new(
            sample.keyexpr.to_owned(),
            Vec::new(),
            crate::liveliness::liveliness_kind_of(sample.kind),
        );
        marshal.bind();
        let sample_ptr = marshal.as_loaned();
        // SAFETY + panic discipline identical to `make_subscriber_callback`:
        // the marshal outlives the call, the borrowed sample is valid only for
        // its duration, and an unwind out of the C callback would tear down the
        // drive thread, so it is caught here.
        let ctx = closure.context.0;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            call(sample_ptr, ctx);
        }));
    }
}

pub(crate) fn make_subscriber_callback(
    closure: Arc<CClosure>,
) -> impl FnMut(&dyn SampleView) + Send + 'static {
    move |view: &dyn SampleView| {
        let call = match closure.call {
            Some(f) => f,
            None => return,
        };
        let mut marshal = SampleMarshal::new(
            view.keyexpr().to_owned(),
            view.payload().to_vec(),
            sample_kind_of(view.kind()),
        );
        // Bind AFTER the move out of `new` — the marshal is at its final
        // address only here. See `SampleMarshal::bind`.
        marshal.bind();
        let sample_ptr = marshal.as_loaned();
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
pub(crate) struct PublisherState {
    shared: Arc<SharedSession>,
    keyexpr: String,
    /// Every matching listener declared THROUGH this publisher, retracted when
    /// it goes away. See [`PublisherState::record_matching_listener`].
    matches: StdMutex<Vec<MatchId>>,
}

impl PublisherState {
    /// The declared keyexpr — what the MATCHING plane watches.
    pub(crate) fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// The session registry this publisher publishes through. Cloned rather
    /// than borrowed because a matching listener outlives the borrow: its
    /// handle must reach `undeclare_matching_listener` after the publisher's
    /// `handle_ref` borrow has ended.
    pub(crate) fn shared_session(&self) -> Arc<SharedSession> {
        self.shared.clone()
    }

    /// Remember that `id` was declared through this publisher, so dropping the
    /// publisher retracts it.
    ///
    /// R311y528 — the matching plane's registry SSOT is keyed on the SESSION,
    /// not on the publisher, because the verdict is aggregated across faces.
    /// That is the right SSOT and it created an ownership gap: pico ties its
    /// write-filter context to the publisher, so `z_undeclare_publisher` there
    /// takes the callbacks with it, while here nothing did — the [`MatchEntry`]
    /// stayed registered, every per-face wz listener stayed installed, and the C
    /// closure kept being invoked for a publisher the program had already
    /// dropped. This list is the missing back-reference.
    ///
    /// [`MatchEntry`]: wz_capi_core::faces::SharedSession::declare_matching_listener
    pub(crate) fn record_matching_listener(&self, id: MatchId) {
        self.matches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(id);
    }
}

/// Retracting on DROP rather than inside `z_undeclare_publisher` is the point:
/// `z_publisher_drop` reaches the same state through `free_publisher`, and
/// putting the retraction in only one of the two exports is exactly how the leak
/// would come back. Every path that releases a `PublisherState` runs this.
///
/// Retraction is idempotent by construction — `undeclare_matching_listener`
/// searches the registry by id and does nothing when the entry is gone — so a C
/// program that undeclares its listener first and its publisher second (the
/// ordinary case) is not double-retracting anything.
impl Drop for PublisherState {
    fn drop(&mut self) {
        // The guard is a temporary of this statement, so the loop below runs
        // with the list UNLOCKED: releasing the last `MatchingSink` runs the C
        // `drop(context)`, which is entitled to re-enter the session.
        let ids = std::mem::take(
            &mut *self
                .matches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for id in ids {
            self.shared.undeclare_matching_listener(id);
        }
    }
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
pub(crate) struct SubscriberState {
    pub(crate) shared: Arc<SharedSession>,
    pub(crate) id: SubId,
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
///
/// # Safety
/// `payload` must be null or a valid `z_moved_bytes_t` whose handle is a live
/// `Box::into_raw::<ByteBuf>` pointer.
pub(crate) unsafe fn take_moved_bytes(payload: *mut z_moved_bytes_t) -> Option<Vec<u8>> {
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
        // A keyexpr that carries a live declaration publishes ALIASED — the
        // wire carries the id instead of the literal, which is the entire
        // reason `z_declare_keyexpr` exists (pico's `_z_write` reads the same
        // discriminant off its `_z_declared_keyexpr_t`). Each face resolves the
        // literal from its own outbound mapping table, so this is correct even
        // for a face that joined after the declaration and got it by replay.
        let result = match keyexpr_mapping(keyexpr) {
            Some(mapping) => state
                .shared
                .publish_aliased_all(mapping, &buf, &put_options()),
            None => state.shared.publish_all(ke, &buf, &put_options()),
        };
        match result {
            Ok(_) => Z_OK,
            Err(_) => Z_ERR_GENERIC,
        }
    })
}

// --- publisher exports -----------------------------------------------------

/// pico `z_publisher_options_t` (`api/types.h:236-247`), 24 B measured against
/// the CMake-GENERATED config these programs compile with.
///
/// The tail of this struct is FEATURE-CONDITIONAL in pico's header, so the
/// layout is a property of the generated `config.h`, not of the source tree:
/// `reliability` exists because `Z_FEATURE_UNSTABLE_API` is defined, and
/// `allowed_destination` is ABSENT because `Z_FEATURE_LOCAL_SUBSCRIBER` is 0.
/// Reading that off the cmake command line instead of the generated header is
/// the R311y466 trap; both were read off `config.h`, and the offsets are pinned
/// in this module's tests.
///
/// wz's `z_declare_publisher` does not yet READ these fields (its options
/// parameter is still `*const c_void`), and that is stated rather than implied:
/// this type exists so a pico program can stack-allocate and default it, which
/// is what `z_pub_thr.c` does. Honouring `congestion_control` / `priority` /
/// `is_express` / `reliability` on the declared publisher is separate surface.
#[repr(C)]
pub struct z_publisher_options_t {
    /// Moved default encoding, or NULL. Typed as an opaque pointer here because
    /// this crate has no encoding plane yet; the SLOT must exist and be 8 B
    /// wide or every field after it lands at the wrong offset.
    pub encoding: *mut c_void,
    pub congestion_control: c_int,
    pub priority: c_int,
    pub is_express: bool,
    pub reliability: c_int,
}

/// Default publisher options (pico `z_publisher_options_default`).
///
/// pico zeroes the encoding slot and takes the library defaults for the rest;
/// the numeric defaults are its enum zero values, which is what a
/// `memset`-style default yields and what `z_pub_thr.c` then publishes with.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_options_default(options: *mut z_publisher_options_t) {
    if options.is_null() {
        return;
    }
    *options = z_publisher_options_t {
        encoding: std::ptr::null_mut(),
        congestion_control: 0,
        priority: 0,
        is_express: false,
        reliability: 0,
    };
}

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
            matches: StdMutex::new(Vec::new()),
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
    crate::ffi::guard_val(false, || !closure.is_null() && (*closure).call.is_some())
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
        let cclosure = CClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        // Reject a non-canonical / pico-unsafe keyexpr UP FRONT (e.g. the
        // `**/c/*` three-family bug), returning `Z_ERR_INVALID` rather than
        // recording a dead SSOT entry that never matches yet reports `Z_OK`.
        // This is the same outbound gate wz's own `Session::declare_subscriber`
        // applies per face — hoisted here so the verdict is uniform whether or
        // not a peer is connected yet (the registry declares best-effort per
        // face, so a per-face reject would otherwise be swallowed). `cclosure`
        // is already owned, so this early return drops it and runs the C
        // `drop(context)` (consume-on-all-paths).
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_ERR_INVALID;
        }

        // Record the subscription in the session's SSOT and declare it on every
        // face that is already up. With no peer yet — a listener before its
        // first connection — this declares nothing on the wire and still
        // records the entry (pico's declare-before-peer); each face replays the
        // SSOT as it comes up. Recording the local entry always succeeds
        // (mirrors pico's `_z_register_subscriber`).
        let id = state.shared.declare_subscriber(ke, {
            let closure = Arc::new(cclosure);
            Arc::new(move || Box::new(make_subscriber_callback(closure.clone())) as Box<_>)
        });
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

/// Declare a subscriber with NO owned handle (pico
/// `z_declare_background_subscriber`). Consumes the moved closure.
///
/// The subscription lives for the session's lifetime and the caller gets
/// nothing back to undeclare it with — pico's "background" declaration, used by
/// programs that subscribe once and then loop forever. Upstream's `z_ping.c`,
/// `z_pong.c` and `z_sub_thr.c` all take this form, which is why one export
/// unlocks three examples.
///
/// Everything except the handle is [`z_declare_subscriber`]: same SSOT
/// registration, same declare-before-peer replay, same up-front keyexpr gate,
/// same consume-on-all-paths closure contract. The registry entry is simply
/// never removed, and `z_close` clears it with the rest of the session — which
/// is also where the C `drop(context)` finally runs.
#[no_mangle]
pub unsafe extern "C" fn z_declare_background_subscriber(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    _options: *const c_void,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        let owned = &mut (*callback)._this;
        let cclosure = CClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_ERR_INVALID;
        }
        // The returned SubId is deliberately discarded: with no owned handle
        // there is nothing that could ever undeclare it, so retaining the id
        // would only invite a caller-less removal path that pico does not have.
        let _ = state.shared.declare_subscriber(ke, {
            let closure = Arc::new(cclosure);
            Arc::new(move || Box::new(make_subscriber_callback(closure.clone())) as Box<_>)
        });
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

/// How the sample was issued — Put or Delete (pico `z_sample_kind`).
///
/// R311y296 exports this because the REPLY plane made it load-bearing rather
/// than merely nice to have: `z_reply_ok` hands the C side a
/// `z_loaned_sample_t`, and R3a's `z_query_reply_del` can emit a Del reply, so
/// without this accessor a C getter could not distinguish a delete reply from a
/// Put carrying an empty payload. R1 shipped only `z_sample_keyexpr` /
/// `z_sample_payload` because a pub/sub-only surface had no Del to observe
/// (`z_delete` rides pico's `Z_FEATURE_PUBLICATION` gate and is still not
/// exported), which left a hole the moment the two planes composed.
///
/// A null / spent sample reports `Z_SAMPLE_KIND_PUT`, which is pico's own
/// `Z_SAMPLE_KIND_DEFAULT` (pico would dereference and crash).
#[no_mangle]
pub unsafe extern "C" fn z_sample_kind(sample: *const z_loaned_sample_t) -> z_sample_kind_t {
    crate::ffi::guard_val(Z_SAMPLE_KIND_PUT, || {
        if sample.is_null() {
            return Z_SAMPLE_KIND_PUT;
        }
        (*(sample as *const SampleMarshal)).kind
    })
}

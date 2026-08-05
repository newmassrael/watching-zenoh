// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The GET plane: `z_get`, the reply closure it consumes, and the borrowed
//! reply a callback reads.
//!
//! ## The C `drop(context)` IS the completion signal
//!
//! zenoh-c reports "this get is over" by running the reply closure's
//! `drop(context)`, not by a distinct final callback. So the closure is adopted
//! FIRST and the source nulled, and every early error return below completes the
//! get exactly as upstream does — including the zero-face case, where the
//! caller's own clone is the last one and the drop runs on the C thread before
//! `z_get` returns.
//!
//! ## The fan holds a guard for the whole loop
//!
//! One C get is issued on every connected face. The C thread keeps its own
//! `Arc` clone across the loop, because a face that answers and finalises before
//! the NEXT face's query is issued would otherwise take the refcount to zero and
//! complete the get while it was still being issued.
//!
//! ## Replies are admitted by the `reply ⊆ query` gate on RECEIVE too
//!
//! A foreign peer is free to answer under a key the query does not cover, and
//! upstream drops such a reply BEFORE building it — the callback never sees it.
//! The gate is [`crate::query::reply_keyexpr_is_covered`], the same SSOT the
//! responder side enforces, so the two halves cannot drift apart.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::sync::Arc;

use wz_runtime_tokio::reply_sink::{ReplyKind, ReplyView};
use wz_runtime_tokio::sample::SampleKind;
use wz_runtime_tokio::session::QueryOptions;

use crate::abi::{
    z_closure_drop_callback_t, z_closure_reply_callback_t, z_loaned_bytes_t, z_loaned_keyexpr_t,
    z_loaned_reply_err_t, z_loaned_reply_t, z_loaned_sample_t, z_loaned_session_t, z_moved_bytes_t,
    z_moved_closure_reply_t, z_moved_reply_t, z_owned_closure_reply_t, z_owned_reply_t, Handle,
    Z_SAMPLE_KIND_PUT,
};
use crate::bytes::BytesState;
use crate::ffi::{guard_val, guarded, CClosure as FfiClosure};
use crate::keyexpr::keyexpr_str;
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::sample::{sample_kind_of, SampleMarshal};
use crate::session::session_state;

use wz_capi_core::faces::SharedSession;

/// The Rust-side wrapper a get's per-face reply callbacks share.
pub(crate) type CReplyClosure = FfiClosure<z_closure_reply_callback_t>;

// SAFETY: the same argument as `crate::sub`'s. A get's callbacks run only on the
// session's single drive task, and `drop` runs when the last `Arc` is released,
// which cannot overlap a live `call`.
unsafe impl Sync for CReplyClosure {}

/// `Z_QUERY_TARGET_BEST_MATCHING` = 0.
pub const Z_QUERY_TARGET_BEST_MATCHING: c_int = 0;
/// `Z_CONSOLIDATION_MODE_AUTO` = -1. NEGATIVE, which is why the field is a
/// signed `c_int` and not an index.
pub const Z_CONSOLIDATION_MODE_AUTO: c_int = -1;

/// `ZC_REPLY_KEYEXPR_ANY` = 0 — replies to any keyexpr query.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub const ZC_REPLY_KEYEXPR_ANY: c_int = 0;
/// `ZC_REPLY_KEYEXPR_MATCHING_QUERY` = 1 — upstream's default
/// (`ReplyKeyExpr::default()`); replies only to intersecting queries.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub const ZC_REPLY_KEYEXPR_MATCHING_QUERY: c_int = 1;

/// zenoh-c `z_query_consolidation_t` — a one-field wrapper around the mode.
#[repr(C)]
pub struct z_query_consolidation_t {
    /// The consolidation mode.
    pub mode: c_int,
}

/// zenoh-c `z_get_options_t` (`zenoh_commons.h:801-831`).
///
/// Mirrored FIELD FOR FIELD, both feature arms, so rustc computes the size from
/// the same list the header declares — the discipline R311y538 established for
/// the publisher options structs, and the reason this type is 56 bytes on the
/// no-unstable oracle and 72 with `Z_FEATURE_UNSTABLE_API`.
#[repr(C)]
pub struct z_get_options_t {
    /// Reply target hint. CARRIED.
    pub target: c_int,
    /// Reply consolidation. CARRIED.
    pub consolidation: z_query_consolidation_t,
    /// Query VALUE payload. CARRIED — consumed by [`z_get`].
    pub payload: *mut z_moved_bytes_t,
    /// Value encoding for the query payload. R311y547 — READ, and carried in
    /// the Query value ext alongside the payload. Typed now that it is used.
    pub encoding: *mut crate::abi::z_moved_encoding_t,
    /// Congestion control. R311y551 — HONOURED: packed into the Request QoS
    /// ext alongside `priority` / `is_express`.
    pub congestion_control: c_int,
    /// Express flag. R311y551 — HONOURED (bit 4 of the Request QoS byte).
    pub is_express: bool,
    /// Destination locality. R311y554 — HONOURED. Note what "ignored" meant
    /// before: `QueryOptions`' own default is `Any`, so a caller who wrote
    /// REMOTE still got the in-process fan.
    pub allowed_destination: c_int,
    /// Which reply keyexprs are accepted — present only under
    /// `Z_FEATURE_UNSTABLE_API`.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub accept_replies: c_int,
    /// Priority. R311y551 — HONOURED (bits 0-2 of the Request QoS byte).
    pub priority: c_int,
    /// Querier source info — unstable-only.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub source_info: *mut c_void,
    /// Query attachment. CARRIED — consumed by [`z_get`].
    pub attachment: *mut z_moved_bytes_t,
    /// Timeout in milliseconds. CARRIED.
    pub timeout_ms: u64,
}

/// The default target (zenoh-c `z_query_target_default`).
///
/// # Safety
/// Takes no pointers; `unsafe` only because every export here shares one
/// signature discipline.
#[no_mangle]
pub unsafe extern "C" fn z_query_target_default() -> c_int {
    Z_QUERY_TARGET_BEST_MATCHING
}

/// Fill default get options (zenoh-c `z_get_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_get_options_default(this_: *mut z_get_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_get_options_t {
            target: Z_QUERY_TARGET_BEST_MATCHING,
            consolidation: z_query_consolidation_t {
                mode: Z_CONSOLIDATION_MODE_AUTO,
            },
            payload: std::ptr::null_mut(),
            encoding: std::ptr::null_mut(),
            // R311y545 — BLOCK, and it is 0 in zenoh-c (the enum is
            // INVERTED against zenoh-pico's). This literal was 1, which
            // spells DROP here; upstream's request-side default is
            // `CongestionControl::DEFAULT_REQUEST` = Block. Named rather
            // than a literal now, because the literal is what went wrong.
            congestion_control: crate::publisher::Z_CONGESTION_CONTROL_BLOCK,
            is_express: false,
            allowed_destination: 0,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            // R311y545 — MATCHING_QUERY (1), MEASURED against the real
            // libzenohc on the unstable oracle; upstream's default is
            // `ReplyKeyExpr::default()`, not ANY. This was 0, and Layer
            // C1cc cannot see it: the field exists only under
            // Z_FEATURE_UNSTABLE_API, which the installed header lacks.
            accept_replies: ZC_REPLY_KEYEXPR_MATCHING_QUERY,
            priority: 5,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: std::ptr::null_mut(),
            attachment: std::ptr::null_mut(),
            // 0 means "use the default", not "never expire" — the runtime
            // resolves it, exactly as upstream does.
            timeout_ms: 0,
        }
    };
}

/// The owned marshal behind a borrowed `z_loaned_reply_t`.
///
/// The Ok arm reuses [`SampleMarshal`] because `z_reply_ok` must hand back a
/// `z_loaned_sample_t*` — so every sample accessor serves this plane unchanged.
pub(crate) struct ReplyMarshal {
    is_ok: bool,
    sample: SampleMarshal,
    /// The Err blob, meaningful iff `!is_ok`.
    err_payload: BytesState,
    loaned_err_payload: z_loaned_bytes_t,
}

impl ReplyMarshal {
    /// Build the marshal for one inbound reply, cached views still UNBOUND.
    fn new(view: &dyn ReplyView) -> Self {
        let kind = view.kind();
        let is_ok = !matches!(kind, ReplyKind::Err);
        // A Del reply carries no payload bytes; an Err's payload is the error
        // blob and belongs on the err arm, not the sample.
        let (sample_payload, err_payload) = match kind {
            ReplyKind::Put => (view.payload().to_vec(), Vec::new()),
            ReplyKind::Del => (Vec::new(), Vec::new()),
            ReplyKind::Err => (Vec::new(), view.payload().to_vec()),
        };
        let sample_kind = match kind {
            ReplyKind::Del => sample_kind_of(SampleKind::Del),
            // Only Put/Del reach a sample; the Err arm's value is inert (the C
            // side must gate on `z_reply_is_ok` before `z_reply_ok`).
            _ => Z_SAMPLE_KIND_PUT,
        };
        Self {
            is_ok,
            sample: SampleMarshal::new(
                view.keyexpr().to_owned(),
                sample_payload,
                // The reply's attachment rides its sample: it is carried on the
                // Put reply's inner body, and dropping it here would make a
                // foreign queryable's metadata invisible.
                view.attachment().map(<[u8]>::to_vec),
                sample_kind,
            ),
            err_payload: BytesState::whole(err_payload),
            loaned_err_payload: z_loaned_bytes_t::null_value(),
        }
    }

    /// Point every cached view at this marshal's own fields.
    fn bind(&mut self) {
        self.sample.bind();
        self.loaned_err_payload =
            z_loaned_bytes_t::from_handle(&self.err_payload as *const BytesState as *mut c_void);
    }

    /// An INDEPENDENT copy, for a reply CHANNEL to escape the callback with.
    fn deep_copy(&self) -> Self {
        Self {
            is_ok: self.is_ok,
            sample: self.sample.deep_copy(),
            err_payload: BytesState::whole(self.err_payload.payload.clone()),
            loaned_err_payload: z_loaned_bytes_t::null_value(),
        }
    }
}

/// Read the marshal behind a loaned reply.
///
/// # Safety
/// `this_` must be null or a pointer this crate handed to a reply callback (or
/// minted by [`z_reply_loan`]) whose marshal is still alive.
unsafe fn reply_marshal<'a>(this_: *const z_loaned_reply_t) -> Option<&'a ReplyMarshal> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { &*(this_ as *const ReplyMarshal) })
}

/// Escape a borrowed reply onto the heap, bound at its final address — what a
/// reply CHANNEL does when the callback hands it a reply.
///
/// # Safety
/// `src` must be null or a pointer this crate handed to a reply callback.
pub(crate) unsafe fn escape_reply(src: *const z_loaned_reply_t) -> Handle {
    // SAFETY: the caller's contract, delegated.
    let Some(marshal) = (unsafe { reply_marshal(src) }) else {
        return std::ptr::null_mut();
    };
    let mut boxed = Box::new(marshal.deep_copy());
    boxed.bind();
    Box::into_raw(boxed) as Handle
}

/// The admission gate one get applies to every inbound reply.
pub(crate) struct ReplyGate {
    /// The keyexpr the get asked under.
    pub(crate) query_keyexpr: String,
    /// Whether the selector waives the coverage check.
    pub(crate) anyke: bool,
}

/// Fire the C reply callback for one inbound reply on one face.
pub(crate) fn fire_reply(closure: &CReplyClosure, gate: &ReplyGate, view: &dyn ReplyView) {
    let Some(call) = closure.call else {
        return;
    };
    // Dropped BEFORE the marshal is built — upstream's callback never sees a
    // reply the query does not accept.
    if !crate::query::reply_keyexpr_is_covered(&gate.query_keyexpr, view.keyexpr(), gate.anyke) {
        return;
    }
    let mut marshal = ReplyMarshal::new(view);
    // Bind AFTER the move out of `new` — final address only here.
    marshal.bind();
    let reply_ptr = &mut marshal as *mut ReplyMarshal as *mut z_loaned_reply_t;
    let ctx = closure.context.0;
    // SAFETY: `call` is the C callback and `marshal` outlives it; the borrowed
    // reply is valid only for its duration. A panic unwinding across the C
    // boundary is UB, so it is caught.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        call(reply_ptr, ctx);
    }));
}

// --- the closure exports ----------------------------------------------------

/// Construct a reply closure from its parts (zenoh-c `z_closure_reply`).
///
/// # Safety
/// `this_` must be valid and writable; `call` / `drop` must be null or valid C
/// function pointers.
#[no_mangle]
pub unsafe extern "C" fn z_closure_reply(
    this_: *mut z_owned_closure_reply_t,
    call: z_closure_reply_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = z_owned_closure_reply_t {
                context,
                call,
                drop,
            }
        };
    });
}

/// Drop a reply closure that was never used (zenoh-c `z_closure_reply_drop`).
///
/// # Safety
/// `closure_` must be null or a valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_reply_drop(closure_: *mut z_moved_closure_reply_t) {
    let _ = guarded(|| {
        if closure_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*closure_)._this };
        if let Some(dropfn) = owned.drop {
            let ctx = owned.context;
            // SAFETY: upstream's contract — drop runs once; unwinds are caught.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                dropfn(ctx);
            }));
        }
        *owned = z_owned_closure_reply_t::null_value();
        Z_OK
    });
}

/// Adopt a moved reply closure and null the source.
///
/// From here the returned `Arc` owns the C `drop(context)`, and because that
/// drop IS the get's completion signal, releasing it on an error path correctly
/// reports "this get is over". Shared with [`crate::querier`] and
/// [`crate::liveliness`], which have the same contract.
///
/// # Safety
/// `callback` must be a non-null, valid moved reply closure.
pub(crate) unsafe fn adopt_reply_closure(
    callback: *mut z_moved_closure_reply_t,
) -> Arc<CReplyClosure> {
    // SAFETY: the caller's contract.
    let owned = unsafe { &mut (*callback)._this };
    let adopted = Arc::new(CReplyClosure::new(owned.context, owned.call, owned.drop));
    *owned = z_owned_closure_reply_t::null_value();
    adopted
}

// --- the reply accessors ----------------------------------------------------

/// `true` iff the reply carries data rather than an error (zenoh-c
/// `z_reply_is_ok`).
///
/// A gravestone reads as NOT ok, so a C program that checks this before
/// `z_reply_ok` never dereferences one.
///
/// # Safety
/// `this_` must be null or a live loaned reply.
#[no_mangle]
pub unsafe extern "C" fn z_reply_is_ok(this_: *const z_loaned_reply_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { reply_marshal(this_) }.is_some_and(|m| m.is_ok)
    })
}

/// Borrow the reply's sample (zenoh-c `z_reply_ok`).
///
/// # Safety
/// `this_` must be null or a live loaned reply.
#[no_mangle]
pub unsafe extern "C" fn z_reply_ok(this_: *const z_loaned_reply_t) -> *const z_loaned_sample_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { reply_marshal(this_) } {
            Some(m) if m.is_ok => m.sample.as_loaned(),
            _ => std::ptr::null(),
        }
    })
}

/// Borrow the reply's ERROR (zenoh-c `z_reply_err`).
///
/// Exported even though no upstream example in the corpus calls it: a C program
/// that branches on `!z_reply_is_ok` has nothing to read without it, so leaving
/// it out would ship a reply plane whose error arm is unreachable.
///
/// # Safety
/// `this_` must be null or a live loaned reply.
#[no_mangle]
pub unsafe extern "C" fn z_reply_err(
    this_: *const z_loaned_reply_t,
) -> *const z_loaned_reply_err_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { reply_marshal(this_) } {
            Some(m) if !m.is_ok => m as *const ReplyMarshal as *const z_loaned_reply_err_t,
            _ => std::ptr::null(),
        }
    })
}

/// Borrow the error's payload (zenoh-c `z_reply_err_payload`).
///
/// # Safety
/// `this_` must be null or a live loaned reply error.
#[no_mangle]
pub unsafe extern "C" fn z_reply_err_payload(
    this_: *const z_loaned_reply_err_t,
) -> *const z_loaned_bytes_t {
    guard_val(std::ptr::null(), || {
        if this_.is_null() {
            return std::ptr::null();
        }
        // SAFETY: `z_reply_err` mints this pointer from a `ReplyMarshal`.
        let m = unsafe { &*(this_ as *const ReplyMarshal) };
        &m.loaned_err_payload as *const z_loaned_bytes_t
    })
}

/// Borrow an owned reply (zenoh-c `z_reply_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned reply.
#[no_mangle]
pub unsafe extern "C" fn z_reply_loan(this_: *const z_owned_reply_t) -> *const z_loaned_reply_t {
    guard_val(std::ptr::null(), || {
        if this_.is_null() {
            return std::ptr::null();
        }
        // The handle IS the marshal pointer — a loan reads slot 0.
        // SAFETY: the caller's contract.
        unsafe { (*this_).handle as *const z_loaned_reply_t }
    })
}

/// `true` iff the owned reply holds a live marshal (zenoh-c
/// `z_internal_reply_check`).
///
/// # Safety
/// `this_` must be null or a valid owned reply.
#[no_mangle]
pub unsafe extern "C" fn z_internal_reply_check(this_: *const z_owned_reply_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned reply (zenoh-c `z_internal_reply_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned reply.
#[no_mangle]
pub unsafe extern "C" fn z_internal_reply_null(this_: *mut z_owned_reply_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_reply_t::null_value() };
    }
}

/// Free an owned reply (zenoh-c `z_reply_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved reply.
#[no_mangle]
pub unsafe extern "C" fn z_reply_drop(this_: *mut z_moved_reply_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<ReplyMarshal>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut ReplyMarshal) });
            unsafe { (*this_)._this = z_owned_reply_t::null_value() };
        }
        Z_OK
    });
}

// --- z_get ------------------------------------------------------------------

/// Issue one get on an already-resolved registry, fanned across every face.
///
/// Shared with [`crate::querier`], which differs only in where the keyexpr and
/// options come from. Duplicating this would put the receive-side [`ReplyGate`]
/// in two places, and the gate must agree with what was transmitted or a reply
/// is silently dropped.
pub(crate) fn issue_get(
    shared: &Arc<SharedSession>,
    keyexpr: String,
    parameters: Option<Vec<u8>>,
    opts: QueryOptions,
    closure: Arc<CReplyClosure>,
) -> ZResult {
    let anyke = parameters
        .as_deref()
        .is_some_and(crate::query::parameters_has_anyke);
    let gate = Arc::new(ReplyGate {
        query_keyexpr: keyexpr.clone(),
        anyke,
    });
    let opts = match parameters {
        Some(params) if !params.is_empty() => opts.with_parameters(params),
        _ => opts,
    };

    // R311y554 — the same one-local-leg split as the fan-out publish, and here
    // it is load-bearing in BOTH directions. A C session's queryable is
    // replayed onto every face, so handing an `Any` get to each face would run
    // the ONE C query handler once per face and answer a single `z_get` N
    // times. The local leg is a property of the session, so it is issued
    // exactly once, on the first face, as `SessionLocal` (which suppresses that
    // face's wire leg — the loop already sent it).
    //
    // With no face at all there is no session to run the local leg on, the same
    // named divergence `SharedSession::publish_all` documents on the publish
    // side.
    use wz_runtime_tokio::locality::Locality;
    let want_remote = opts.allowed_destination.allows_remote();
    let mut local_pending = opts.allowed_destination.allows_local();

    // The C thread's own clone, held across the whole loop — see the module doc
    // for why a face that finalises early must not be able to complete the get
    // while later faces are still being issued.
    let guard = closure.clone();
    for (session, revised) in shared.face_sessions_with_wake() {
        // The face that carries the session's single local leg carries it IN
        // ADDITION to its own wire leg — ONE `query` call at the caller's own
        // locality, not two, because a second call would register a second
        // pending entry and so deliver a second Final for one `z_get`.
        let per_face_locality = match (std::mem::take(&mut local_pending), want_remote) {
            (true, true) => Locality::Any,
            (true, false) => Locality::SessionLocal,
            (false, true) => Locality::Remote,
            // A local-only get whose one local leg is already placed: the
            // remaining faces have nothing to do, and issuing a Remote query
            // on them would send exactly what the caller asked us not to.
            (false, false) => continue,
        };
        let per_face = closure.clone();
        let per_face_gate = gate.clone();
        // Only `on_reply` carries the `Arc`. Completion is signalled by the
        // pending entry's sink being DROPPED, which covers a real final, a
        // timeout sweep and a face death alike — whereas a counter incremented
        // in `on_final` would never be reached by the face-death path.
        let issued = session.query(
            &keyexpr,
            opts.clone().with_allowed_destination(per_face_locality),
            move |view: &dyn ReplyView| fire_reply(&per_face, &per_face_gate, view),
            |_rid| {},
        );
        // A per-face issue error (a face mid-teardown) is swallowed, matching
        // the fan-out publish's best-effort discipline; its clone was already
        // dropped with the rolled-back sink.
        drop(issued);
        // Wake this face's drive loop so it re-arms on the deadline just
        // registered; without it a silent session sweeps only at the next
        // keepalive wake.
        revised.notify_one();
    }
    drop(guard);
    Z_OK
}

/// Turn a `z_get_options_t` into wz [`QueryOptions`].
///
/// A NULL pointer is upstream's "defaults", not an error.
///
/// # Safety
/// `options` must be null or a valid get options struct; its `payload` and
/// `attachment` are CONSUMED.
unsafe fn get_options(options: *mut z_get_options_t) -> QueryOptions {
    let mut opts = QueryOptions::default();
    if options.is_null() {
        return opts;
    }
    // SAFETY: the caller's contract.
    let o = unsafe { &mut *options };
    // wz's timeout field is a `u32`; SATURATE rather than wrap, because a
    // wrapped huge timeout becomes a tiny one and expires the get immediately.
    opts = opts.with_timeout_ms(o.timeout_ms.min(u32::MAX as u64) as u32);
    if let Some(target) = query_target_of(o.target) {
        opts = opts.with_target(target);
    }
    if let Some(mode) = consolidation_of(o.consolidation.mode) {
        opts = opts.with_consolidation(mode);
    }
    // SAFETY: the caller's contract — both are moved values this consumes.
    if let Some(payload) = unsafe { crate::bytes::take_payload(o.payload) } {
        opts = opts.with_payload(payload);
    }
    // R311y547 — the query VALUE's encoding. `payload` + `encoding` collapse
    // into the wire `_z_value_t` pair that `QueryMetadata::value` threads onto
    // `RequestQueryBuilder::query_value` (the Q_B / Q_E value ext 0x03), so a
    // querier that set one was previously sending its payload with the default
    // label. READ rather than taken, for the reason
    // `crate::encoding::moved_encoding_hint` documents.
    // SAFETY: the caller's contract.
    if let Some(hint) = unsafe { crate::encoding::moved_encoding_hint(o.encoding) } {
        opts = opts.with_encoding(hint);
    }
    if let Some(attachment) = unsafe { crate::bytes::take_payload(o.attachment) } {
        opts = opts.with_attachment(attachment);
    }
    // R311y551 — the request-side QoS trio. Until this round all three were
    // "accepted and ignored": `QueryOptions` had no slot to put them in, so a
    // program that asked for express delivery at `Z_PRIORITY_REAL_TIME` was
    // correct about the API and sent an ordinary Data-priority query. They ride
    // ONE packed byte (the Request outer ext `_Z_MSG_EXT_ENC_ZINT | 0x01`), so
    // all three are set unconditionally rather than each behind an
    // is-it-non-default test: the suppression of a fully-default byte belongs
    // at the single wire seam in `build_request_query_with_meta`, not smeared
    // across three call sites that cannot see each other's contribution.
    opts = opts
        .with_priority(crate::publisher::priority_from_c(o.priority))
        .with_congestion_control(crate::publisher::congestion_from_c(o.congestion_control))
        .with_express(o.is_express);
    // R311y554 — `allowed_destination` is HONOURED. The default was already
    // `Locality::Any` on the wz side, so the pre-y554 code did not merely ignore
    // this field: it ignored a caller who wrote REMOTE and ran the in-process
    // fan anyway. `fan_get` is what keeps the local half from running once per
    // face.
    opts = opts.with_allowed_destination(crate::put::locality_from_c(o.allowed_destination));
    opts
}

/// zenoh-c's target constant as a wz target. An unknown value is `None`, which
/// leaves the wire byte elided and the peer reading its own default — the same
/// outcome as `BEST_MATCHING`, and better than mapping garbage onto `ALL`.
pub(crate) fn query_target_of(
    target: c_int,
) -> Option<wz_runtime_tokio::session_glue::QueryTarget> {
    use wz_runtime_tokio::session_glue::QueryTarget;
    match target {
        1 => Some(QueryTarget::All),
        2 => Some(QueryTarget::AllComplete),
        _ => None,
    }
}

/// zenoh-c's consolidation constant as a wz mode. `AUTO` (-1) is `None`: the
/// wire byte is elided and the peer applies its own default, which is what AUTO
/// means.
pub(crate) fn consolidation_of(
    mode: c_int,
) -> Option<wz_runtime_tokio::session_glue::ConsolidationMode> {
    use wz_runtime_tokio::session_glue::ConsolidationMode;
    match mode {
        0 => Some(ConsolidationMode::None),
        1 => Some(ConsolidationMode::Monotonic),
        2 => Some(ConsolidationMode::Latest),
        _ => None,
    }
}

/// Query the network (zenoh-c `z_get`). Consumes the moved closure on every
/// path.
///
/// # Safety
/// `session` must be a valid loaned session; `key_expr` must be a valid loaned
/// keyexpr; `parameters` must be null or NUL-terminated; `callback` must be a
/// valid moved reply closure; `options` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_get(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    parameters: *const c_char,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_get_options_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // Adopt the closure FIRST (consume-on-all-paths): from here every early
        // return completes the get, which is upstream's behaviour.
        // SAFETY: the caller's contract.
        let closure = unsafe { adopt_reply_closure(callback) };
        // The options' moved payload / attachment are consumed here too, on
        // every path, for the same reason.
        // SAFETY: the caller's contract.
        let opts = unsafe { get_options(options) };

        // SAFETY: the caller's contract for both handles.
        let (Some(state), Some(ke)) = (unsafe { session_state(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_EINVAL;
        }
        let params = if parameters.is_null() {
            None
        } else {
            // SAFETY: the caller's contract — NUL-terminated.
            Some(unsafe { CStr::from_ptr(parameters) }.to_bytes().to_vec())
        };
        issue_get(&state.shared, ke, params, opts, closure)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R311y554 — `z_get_options_t.allowed_destination` reaches
    /// [`QueryOptions`], on every value.
    ///
    /// The pre-y554 behaviour was not "ignored": `QueryOptions`' own default is
    /// `Locality::Any`, so a caller who wrote REMOTE still got the in-process
    /// fan. A field that is dropped in the direction that RELAXES the request is
    /// worse than one that is dropped symmetrically, which is why the REMOTE row
    /// of this table is the load-bearing one.
    #[test]
    fn get_options_carry_the_callers_allowed_destination() {
        use wz_runtime_tokio::locality::Locality;
        for (c_value, expected) in [
            (crate::publisher::ZC_LOCALITY_ANY, Locality::Any),
            (
                crate::publisher::ZC_LOCALITY_SESSION_LOCAL,
                Locality::SessionLocal,
            ),
            (crate::publisher::ZC_LOCALITY_REMOTE, Locality::Remote),
        ] {
            let mut o: z_get_options_t = unsafe { std::mem::zeroed() };
            o.allowed_destination = c_value;
            // SAFETY: a live local whose owned pointer fields are all null.
            let resolved = unsafe { get_options(&mut o) };
            assert_eq!(
                resolved.allowed_destination, expected,
                "z_get_options_t.allowed_destination = {c_value} -> {expected:?}",
            );
        }
    }

    /// R311y547 — the query VALUE's encoding reaches [`QueryOptions`].
    ///
    /// ## Why this is a unit test and not a foreign witness
    ///
    /// Stated rather than left to be inferred from its absence: no zenoh-pico
    /// example RENDERS the encoding of a query it received. `z_queryable.c`
    /// prints the query's keyexpr, parameters and value; the build-time patch
    /// this repo applies to it adds the source_info; neither reaches
    /// `z_query_encoding`, and pico's own `z_get_attachment` prints the
    /// encoding of a REPLY, which is the direction
    /// `a_wz_capi_c_queryable_reply_encoding_reaches_a_real_pico_as_it_does_on_libzenohc`
    /// witnesses foreign-side. So this half is proven where it can be proven —
    /// at the seam — and the wire leg is a NON-CLAIM, not an oversight.
    ///
    /// The seam is the load-bearing part regardless: `QueryOptions::encoding`
    /// collapses with `payload` into the `QueryMetadata::value` pair that
    /// `RequestQueryBuilder::query_value` puts on the wire (ext 0x03), and that
    /// path is already byte-pinned by its own tests.
    #[test]
    fn a_get_options_encoding_reaches_the_query_options() {
        let mut opts = z_get_options_t {
            target: crate::get::Z_QUERY_TARGET_BEST_MATCHING,
            consolidation: z_query_consolidation_t {
                mode: crate::get::Z_CONSOLIDATION_MODE_AUTO,
            },
            payload: std::ptr::null_mut(),
            encoding: std::ptr::null_mut(),
            congestion_control: crate::publisher::Z_CONGESTION_CONTROL_BLOCK,
            is_express: false,
            allowed_destination: crate::publisher::ZC_LOCALITY_ANY,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            accept_replies: ZC_REPLY_KEYEXPR_MATCHING_QUERY,
            priority: crate::publisher::Z_PRIORITY_DATA,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: std::ptr::null_mut(),
            attachment: std::ptr::null_mut(),
            timeout_ms: 0,
        };
        // No encoding set: the slot stays empty, so the assertion below cannot
        // pass on a build that hard-codes one.
        // SAFETY: a live local.
        let bare = unsafe { get_options(&mut opts) };
        assert!(
            bare.encoding.is_none(),
            "an unset encoding must not synthesise one"
        );

        // `z_encoding_text_plain()` hands back a `'static` loaned view; the
        // moved wrapper the C side would build is the owned value at offset 0,
        // which is the same footprint.
        let mut owned = crate::abi::z_owned_encoding_t::null_value();
        // SAFETY: live locals, valid for the call.
        unsafe {
            crate::encoding::z_encoding_clone(&mut owned, crate::encoding::z_encoding_text_plain())
        };
        let mut moved = crate::abi::z_moved_encoding_t { _this: owned };
        opts.encoding = &mut moved as *mut crate::abi::z_moved_encoding_t;
        // SAFETY: a live local.
        let resolved = unsafe { get_options(&mut opts) };
        let hint = resolved
            .encoding
            .expect("a set encoding reaches QueryOptions");
        // `text/plain` is zenoh wire id 4, so the packed word is `4 << 1`. The
        // NUMBER is asserted rather than the label, because the number is what
        // goes on the wire.
        assert_eq!(hint.packed_id, 8);
        assert_eq!(hint.schema, None);
    }

    /// R311y551 — the request-side QoS trio reaches [`QueryOptions`] AND the
    /// wire, end to end, from the zenoh-c option struct.
    ///
    /// This half ends at `QueryOptions.qos`, which is exactly where
    /// `wz-runtime-tokio`'s `query_options_qos_reaches_the_request_wire` picks
    /// it up (`QueryOptions` -> `query_metadata()` -> the Request bytes). The
    /// two meet at that field and nothing between the C struct and the wire is
    /// taken on trust; the split is because `query_metadata` is `pub(super)`
    /// and widening it to prove a test would be the tail wagging the ABI.
    ///
    /// The VALUES matter as much as the plumbing here. zenoh-c's
    /// `z_congestion_control_t` is INVERTED against zenoh-pico's (BLOCK is 0
    /// here, 1 there — R311y545 found that by measurement after shipping the
    /// pico values in this crate), so a mapping that read the sibling ABI's
    /// constant would produce a byte that is wrong in exactly the way no
    /// layout or link check can see.
    #[test]
    fn a_get_options_qos_trio_reaches_the_query_options_and_the_wire() {
        use wz_runtime_tokio::qos::{CongestionControl, Priority};

        let mut opts = z_get_options_t {
            target: crate::get::Z_QUERY_TARGET_BEST_MATCHING,
            consolidation: z_query_consolidation_t {
                mode: crate::get::Z_CONSOLIDATION_MODE_AUTO,
            },
            payload: std::ptr::null_mut(),
            encoding: std::ptr::null_mut(),
            // DROP, which is 1 in zenoh-c. Deliberately the value that is BLOCK
            // in zenoh-pico: a mapping cribbed from the sibling ABI inverts the
            // `nodrop` bit and this assertion is what catches it.
            congestion_control: crate::publisher::Z_CONGESTION_CONTROL_DROP,
            is_express: true,
            allowed_destination: crate::publisher::ZC_LOCALITY_ANY,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            accept_replies: ZC_REPLY_KEYEXPR_MATCHING_QUERY,
            // Z_PRIORITY_REAL_TIME = 1, distinct from the default (5) so an
            // implementation that ignored the field and kept the default would
            // fail rather than coincide.
            priority: 1,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: std::ptr::null_mut(),
            attachment: std::ptr::null_mut(),
            timeout_ms: 0,
        };
        // SAFETY: a live local.
        let resolved = unsafe { get_options(&mut opts) };
        let qos = resolved.qos.expect("the QoS trio reaches QueryOptions");
        assert_eq!(qos.priority(), Priority::RealTime, "priority");
        assert_eq!(qos.congestion(), CongestionControl::Drop, "congestion");
        assert!(qos.is_express(), "express");

        // The DEFAULT options must ALSO populate the slot rather than leaving
        // it `None`: upstream's request-side default is BLOCK, which is NOT the
        // wire DEFAULT byte (DROP), so a default `z_get` legitimately carries a
        // QoS ext. Leaving it unset here would silently downgrade every default
        // query to Drop — the same class of defect as the inverted enum, one
        // layer up.
        // SAFETY: a live local.
        unsafe { z_get_options_default(&mut opts) };
        // SAFETY: a live local.
        let defaulted = unsafe { get_options(&mut opts) };
        let default_qos = defaulted
            .qos
            .expect("the options-default QoS reaches QueryOptions too");
        assert_eq!(default_qos.congestion(), CongestionControl::Block);
        assert_eq!(default_qos.priority(), Priority::Data);
        assert!(!default_qos.is_express());
    }

    /// The defaults are upstream's, and `timeout_ms` is 0 meaning "resolve the
    /// default" — not "never expire", which would leave a get that no peer
    /// answers hanging forever.
    #[test]
    fn the_get_options_default_matches_upstreams() {
        let mut opts = z_get_options_t {
            target: 99,
            consolidation: z_query_consolidation_t { mode: 99 },
            payload: std::ptr::null_mut(),
            encoding: std::ptr::null_mut(),
            congestion_control: 99,
            is_express: true,
            allowed_destination: 99,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            accept_replies: 99,
            priority: 99,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: std::ptr::null_mut(),
            attachment: std::ptr::null_mut(),
            timeout_ms: 99,
        };
        // SAFETY: `opts` is a live local.
        unsafe { z_get_options_default(&mut opts) };
        assert_eq!(opts.target, Z_QUERY_TARGET_BEST_MATCHING);
        assert_eq!(opts.consolidation.mode, Z_CONSOLIDATION_MODE_AUTO);
        assert_eq!(opts.timeout_ms, 0);
        assert!(!opts.is_express);
        // SAFETY: no pointers.
        assert_eq!(unsafe { z_query_target_default() }, opts.target);
    }

    /// AUTO is NEGATIVE (-1), which is the detail an unsigned field or a
    /// zero-default would silently get wrong: it would land on
    /// `Z_CONSOLIDATION_MODE_NONE` and disable consolidation rather than
    /// deferring to the peer.
    #[test]
    fn auto_consolidation_is_negative_and_elides_the_wire_byte() {
        assert_eq!(Z_CONSOLIDATION_MODE_AUTO, -1);
        assert!(consolidation_of(Z_CONSOLIDATION_MODE_AUTO).is_none());
        assert!(consolidation_of(0).is_some());
        assert!(query_target_of(Z_QUERY_TARGET_BEST_MATCHING).is_none());
        assert!(query_target_of(2).is_some());
    }

    /// Every accessor answers a NULL reply without dereferencing it, and a
    /// gravestone reads as NOT ok — the order `z_get.c` relies on.
    #[test]
    fn the_reply_accessors_answer_null_without_dereferencing_it() {
        // SAFETY: passing NULL is exactly what these guards exist for.
        unsafe {
            assert!(!z_reply_is_ok(std::ptr::null()));
            assert!(z_reply_ok(std::ptr::null()).is_null());
            assert!(z_reply_err(std::ptr::null()).is_null());
            assert!(z_reply_loan(std::ptr::null()).is_null());
            assert!(!z_internal_reply_check(std::ptr::null()));
            z_reply_drop(std::ptr::null_mut());
        }
    }
}

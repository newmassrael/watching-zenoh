// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The queryable (responder) half of the pico query plane: `z_closure_query`,
//! `z_declare_queryable` / `z_declare_background_queryable` /
//! `z_undeclare_queryable`, the loaned-query accessors, and
//! `z_query_reply` / `_del` / `_err`.
//!
//! A C queryable is recorded in the session's registry as a SECOND SSOT
//! alongside the subscription one (the `faces` module) and replayed onto every
//! face, so one C declaration answers queries from every connected peer — the
//! responder-side mirror of the subscriber fan-out. Per-face request-id
//! independence (each face's wz session allocates its own request ids) makes
//! cross-face rid collision unrepresentable rather than merely untested.
//!
//! ## What is deliberately NOT exported, and why that is loud
//!
//! The **owned-query family** (`z_query_clone` / `z_query_take_from_loaned` /
//! the `z_owned_query_t` ownership set) is withheld. pico's channel handlers
//! (`include/zenoh-pico/api/handlers.h`, e.g. `z_fifo_channel_query_new`) are
//! `static inline` — they compile into the USER's object file and their bodies
//! call `z_query_take_from_loaned` / `z_query_move` / `z_query_drop`. Exporting
//! that family WITHOUT first building the retained-responder seam wz lacks (see
//! below) would make every channel-based queryable compile, link, and then
//! **silently** fail to answer. Withholding it instead yields an undefined
//! symbol at link time — loud, and the same round boundary R1 drew (R1 shipped
//! pub/sub; a get program failed to link rather than silently no-op).
//!
//! The seam that family needs is a NEW wz core concept, not a binding detail:
//! [`wz_runtime_tokio::query_sink::ReplyOut`] is a borrowed `&mut` reply
//! ACCUMULATOR whose `with_responder` / `clear_responder` only stamp a responder
//! IDENTITY (zid + eid) — not a detachment. Nothing in the tree owns a responder
//! past the callback, and wz sends the `ResponseFinal` once the callback
//! returns. A retained-responder + deferred-final concept must land in
//! wz-session-core before an owned query can outlive its callback.
//!
//! `z_query_encoding` is withheld on the same principle: it returns a
//! `z_loaned_encoding_t`, and the encoding type family is a separate follow-up
//! round. A missing symbol is a link error; a stub returning null would be a
//! silent lie.
//!
//! ## Reply accumulation
//!
//! `z_query_reply` records into this query's marshal and the accumulated
//! replies are flushed into the wz [`ReplyOut`] when the C callback returns.
//! That is observably identical to emitting during the callback, because wz's
//! own responder already accumulates: `QueryResponder` "only accumulates into a
//! `Vec<QueryReply>` that the `codec-response`-gated `into_response` drains"
//! (`wz-session-core/src/query.rs:884-895`), and the `Response`s leave the
//! session after the handler returns either way. Accumulating here in addition
//! buys a strictly smaller unsafe surface: the alternative — stashing the
//! `&mut dyn ReplyOut` as a raw trait-object pointer with its lifetime erased —
//! would need a `transmute` and hand the C side a pointer whose validity we
//! could not check.

use std::cell::UnsafeCell;
use std::ffi::{c_int, c_void};
use std::sync::Arc;

use wz_runtime_tokio::query_sink::{QueryView, ReplyOut};

use crate::abi::{
    handle_ref, impl_handle_ownership7, z_loaned_bytes_t, z_loaned_keyexpr_t, z_moved_bytes_t,
    z_view_string_t,
};
use crate::faces::{QblId, SharedSession};
use crate::ffi::{guarded, SendPtr};
use crate::keyexpr::keyexpr_str;
use crate::result::{ZResult, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
use crate::session::{z_loaned_session_t, SessionState};

// --- pico enum-typed option fields -----------------------------------------
//
// pico's `z_congestion_control_t` / `z_priority_t` are plain C enums, so each
// occupies an `int` in the option structs below. Both are documented
// "Deprecated: ignored, taken from query" on the reply options
// (`~/zenoh-pico/include/zenoh-pico/api/types.h:318-321`), so they are carried
// for layout only.
type z_congestion_control_t = c_int;
type z_priority_t = c_int;

// --- opaque loaned query ---------------------------------------------------

/// Opaque loaned query (pico `z_loaned_query_t`). The C callback only holds a
/// pointer to it and passes it back to the accessors / `z_query_reply`, so this
/// stays opaque rather than reproducing pico's concrete `_z_query_t` layout —
/// the same model `z_loaned_sample_t` uses.
#[repr(C)]
pub struct z_loaned_query_t {
    _opaque: [u8; 0],
}

/// One reply the C callback asked for, held until the callback returns and the
/// batch is flushed into the wz [`ReplyOut`].
enum PendingReply {
    /// `z_query_reply` — a Put-form reply under an explicit keyexpr.
    Put { keyexpr: String, payload: Vec<u8> },
    /// `z_query_reply_del` — a Del-form reply under the query's own keyexpr
    /// (see [`z_query_reply_del`] for why a differing keyexpr is rejected).
    Del,
    /// `z_query_reply_err` — an Err-form reply.
    Err { payload: Vec<u8> },
}

/// The owned marshal behind a borrowed `z_loaned_query_t` during one callback.
///
/// Owns copies of the query's keyexpr / parameters / value payload so they
/// outlive the wz [`QueryView`] borrow, caches the loaned views the accessors
/// hand back, and accumulates the replies the callback asks for.
struct QueryMarshal {
    keyexpr: String,
    parameters: Vec<u8>,
    payload: Vec<u8>,
    has_payload: bool,
    attachment: Vec<u8>,
    has_attachment: bool,
    loaned_keyexpr: z_loaned_keyexpr_t,
    loaned_payload: z_loaned_bytes_t,
    loaned_attachment: z_loaned_bytes_t,
    /// Reply accumulator.
    ///
    /// `UnsafeCell` because the accessors receive `*const z_loaned_query_t` and
    /// must append. The soundness anchor is pico's callback contract, and it is
    /// the ONLY anchor: one query's callback — and any `z_query_reply` on its
    /// loaned query — runs on the session's single read task, so no aliasing
    /// borrow exists while it runs. Here that task is the face's drive thread.
    ///
    /// This marshal is valid for exactly the duration of one `call`, the same
    /// scope pico gives its own `z_loaned_query_t`. Using the pointer after the
    /// callback returns, or from another thread, is undefined behaviour — in
    /// pico too, whose loaned query is only escapable via
    /// `z_query_take_from_loaned` (the owned family this round deliberately
    /// withholds; see the module doc). We add no tripwire for that: an earlier
    /// cut carried a `valid` flag cleared at callback return, but with a
    /// callback-scoped marshal the flag can never usefully fire — after the
    /// frame dies, READING the flag is itself the use-after-free it was meant
    /// to intercept. Keeping it would have documented a protection that does
    /// not exist, which is worse than pico's honest silence.
    replies: UnsafeCell<Vec<PendingReply>>,
}

impl QueryMarshal {
    /// Build the marshal for one inbound query, with its cached views still
    /// UNBOUND — [`Self::bind`] must run once the value has reached its final
    /// address. Splitting the two is load-bearing; see `bind`.
    fn new(view: &dyn QueryView) -> Self {
        let payload = view.payload().map(<[u8]>::to_vec);
        let attachment = view.attachment().map(<[u8]>::to_vec);
        Self {
            keyexpr: view.keyexpr().to_owned(),
            parameters: view.parameters().map(<[u8]>::to_vec).unwrap_or_default(),
            has_payload: payload.is_some(),
            payload: payload.unwrap_or_default(),
            has_attachment: attachment.is_some(),
            attachment: attachment.unwrap_or_default(),
            loaned_keyexpr: z_loaned_keyexpr_t {
                _start: std::ptr::null(),
                _len: 0,
            },
            loaned_payload: z_loaned_bytes_t {
                handle: std::ptr::null_mut(),
                _pad: [std::ptr::null_mut(); 3],
            },
            loaned_attachment: z_loaned_bytes_t {
                handle: std::ptr::null_mut(),
                _pad: [std::ptr::null_mut(); 3],
            },
            replies: UnsafeCell::new(Vec::new()),
        }
    }

    /// Point the cached views at this marshal's own fields.
    ///
    /// MUST run only once the marshal sits at its FINAL address, and must not
    /// be folded back into [`Self::new`]. `loaned_payload.handle` /
    /// `loaned_attachment.handle` store the address of the `Vec` STRUCT (that
    /// is what [`crate::abi::handle_ref`] reconstructs a `&Vec<u8>` from), and
    /// a struct field's address moves with the struct. `new` returns `Self` by
    /// value, so binding inside it would record `new`'s frame and hand C a
    /// pointer into a dead frame the moment the value is moved out — return-
    /// value optimisation is not a language guarantee and does not save it.
    ///
    /// `loaned_keyexpr._start` would in fact survive (`String::as_ptr` is the
    /// HEAP buffer, which a move does not relocate — the same distinction
    /// [`crate::bytes`] documents), and that asymmetry is exactly what made an
    /// earlier binding-inside-`new` pass its test: the test read only the
    /// keyexpr. Both are bound here so the rule is uniform rather than
    /// per-field reasoning.
    ///
    /// Sibling shapes in this crate, for orientation: `SampleMarshal`
    /// (`pubsub.rs`) is built in the callback frame and never moved;
    /// [`QueryableState`] binds after its `Box::new`. Both reach the same
    /// invariant — bind at the final address.
    fn bind(&mut self) {
        self.loaned_keyexpr = z_loaned_keyexpr_t {
            _start: self.keyexpr.as_ptr(),
            _len: self.keyexpr.len(),
        };
        self.loaned_payload.handle = &self.payload as *const Vec<u8> as *mut c_void;
        self.loaned_attachment.handle = &self.attachment as *const Vec<u8> as *mut c_void;
    }

    /// Append a reply the C callback asked for.
    ///
    /// # Safety
    /// Caller must be inside the callback that owns this marshal (the pico
    /// single-threaded-callback contract), so no aliasing borrow of `replies`
    /// exists.
    unsafe fn push_reply(&self, reply: PendingReply) {
        (*self.replies.get()).push(reply);
    }

    /// Flush the accumulated replies into the wz responder. Runs after the C
    /// callback returned, on the drive thread.
    fn flush(&mut self, out: &mut dyn ReplyOut) {
        for reply in self.replies.get_mut().drain(..) {
            match reply {
                PendingReply::Put { keyexpr, payload } => out.reply_keyed(&keyexpr, &payload),
                PendingReply::Del => out.reply_del(),
                PendingReply::Err { payload } => out.reply_err(None, None, &payload),
            }
        }
    }
}

/// Read the marshal behind a loaned query, or `None` if the pointer is null or
/// the marshal is spent (its callback already returned).
///
/// # Safety
/// `query` must be null or a pointer this crate handed to a query callback.
unsafe fn query_marshal<'a>(query: *const z_loaned_query_t) -> Option<&'a QueryMarshal> {
    if query.is_null() {
        return None;
    }
    Some(&*(query as *const QueryMarshal))
}

// --- C closure types -------------------------------------------------------

/// pico `z_closure_query_callback_t`: `void call(z_loaned_query_t*, void*)`.
pub type z_closure_query_callback_t =
    Option<unsafe extern "C" fn(*const z_loaned_query_t, *mut c_void)>;

/// Owned query closure (pico `z_owned_closure_query_t`, 24 B:
/// `{ context, call, drop }` in that field order —
/// `~/zenoh-pico/include/zenoh-pico/api/types.h:730-740`).
#[repr(C)]
pub struct z_owned_closure_query_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_query_callback_t,
    pub(crate) drop: crate::pubsub::z_closure_drop_callback_t,
}

/// Loaned query closure (pico `z_loaned_closure_query_t`), same layout.
#[repr(C)]
pub struct z_loaned_closure_query_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_query_callback_t,
    pub(crate) drop: crate::pubsub::z_closure_drop_callback_t,
}

/// Moved query closure (pico `z_moved_closure_query_t`).
#[repr(C)]
pub struct z_moved_closure_query_t {
    pub(crate) _this: z_owned_closure_query_t,
}

impl z_owned_closure_query_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

/// The Rust-side wrapper one C queryable's per-face callbacks share — the
/// responder-side mirror of [`crate::pubsub::CClosure`]. Its `Drop` invokes the
/// C `drop(context)` exactly once, when the last face's callback and the
/// registry's SSOT entry have both released it.
pub(crate) struct CQueryClosure {
    context: SendPtr,
    call: z_closure_query_callback_t,
    drop: crate::pubsub::z_closure_drop_callback_t,
}

impl CQueryClosure {
    /// Adopt a moved C closure's fields (the caller nulls the source).
    pub(crate) fn new(
        context: *mut c_void,
        call: z_closure_query_callback_t,
        drop: crate::pubsub::z_closure_drop_callback_t,
    ) -> Self {
        Self {
            context: SendPtr(context),
            call,
            drop,
        }
    }
}

impl Drop for CQueryClosure {
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

// SAFETY: identical rationale to `pubsub::CClosure`'s, on the responder plane.
// Sharing one queryable's `CQueryClosure` across a per-face callback needs
// `Sync` (so `Arc<CQueryClosure>`, and each callback, is `Send`). Sharing
// `&CQueryClosure` is sound because `call` is only ever invoked from the
// session's single drive task: every face of a session is driven on ONE task,
// and the queryable handler fires from that task's inbound dispatch drain.
//
// It is load-bearing that the C application thread never invokes `call`. The
// queryable plane's exposure to that is narrower than the subscriber plane's: a
// queryable does not fan on publish, it only answers a query that ARRIVED at a
// face. The one path that could stage a local queryable job on a C thread is
// `Session::query`'s loopback arm — whose drain is gated on `allows_local`
// (`wz-runtime-tokio/src/session/mod.rs:2023`, R311y290), so a Remote-only
// `z_get` stages nothing and drains nothing on the C thread. `drop` runs only
// when the last `Arc` is released, which cannot overlap a live `call` (a running
// callback holds a reference).
unsafe impl Sync for CQueryClosure {}

/// Build the wz-side queryable handler for ONE face from a shared C closure.
///
/// Marshals the wz [`QueryView`] into a borrowed `z_loaned_query_t`, invokes the
/// C `call`, then flushes whatever replies it accumulated into the wz
/// [`ReplyOut`]. The marshal (and so the borrowed keyexpr / payload) is valid
/// only for the duration of that call — pico's contract, which is why the C side
/// must copy anything it keeps.
pub(crate) fn make_queryable_callback(
    closure: Arc<CQueryClosure>,
) -> impl FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static {
    move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
        let call = match closure.call {
            Some(f) => f,
            None => return,
        };
        let mut marshal = QueryMarshal::new(view);
        // Bind AFTER the move out of `new` — the marshal is at its final
        // address only here. See `QueryMarshal::bind`.
        marshal.bind();
        let query_ptr = &marshal as *const QueryMarshal as *const z_loaned_query_t;
        // SAFETY: `call` is the C callback; `marshal` outlives the call and the
        // borrowed query is valid only for its duration (pico contract).
        // `context` travels with the drive dispatch. A panic unwinding OUT of
        // the C callback across this `extern "C"` boundary is UB and would tear
        // down the drive thread, so it is caught here — the drive loop survives
        // a misbehaving callback.
        let ctx = closure.context.0;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            call(query_ptr, ctx);
        }));
        marshal.flush(out);
    }
}

// --- closure_query exports -------------------------------------------------

/// Build an owned query closure from a callback + drop + context (pico
/// `z_closure_query`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_query(
    closure: *mut z_owned_closure_query_t,
    call: z_closure_query_callback_t,
    drop: crate::pubsub::z_closure_drop_callback_t,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        if closure.is_null() {
            return Z_ERR_NULL;
        }
        *closure = z_owned_closure_query_t {
            context,
            call,
            drop,
        };
        Z_OK
    })
}

/// Invoke a query closure directly (pico `z_closure_query_call`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_query_call(
    closure: *const z_loaned_closure_query_t,
    query: *mut z_loaned_query_t,
) {
    let _ = guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        if let Some(call) = (*closure).call {
            call(query, (*closure).context);
        }
        Z_OK
    });
}

/// Zero an owned query closure (pico `z_internal_closure_query_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_query_null(closure: *mut z_owned_closure_query_t) {
    if !closure.is_null() {
        *closure = z_owned_closure_query_t::null_value();
    }
}

/// `true` iff the closure holds a callback (pico
/// `z_internal_closure_query_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_query_check(
    closure: *const z_owned_closure_query_t,
) -> bool {
    crate::ffi::guard_val(false, || !closure.is_null() && (*closure).call.is_some())
}

/// Borrow an owned query closure (pico `z_closure_query_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_query_loan(
    closure: *const z_owned_closure_query_t,
) -> *const z_loaned_closure_query_t {
    closure as *const z_loaned_closure_query_t
}

/// Move-cast an owned query closure (pico `z_closure_query_move`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_query_move(
    closure: *mut z_owned_closure_query_t,
) -> *mut z_moved_closure_query_t {
    closure as *mut z_moved_closure_query_t
}

/// Take an owned query closure out of `src` into `dst` (pico
/// `z_closure_query_take`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_query_take(
    dst: *mut z_owned_closure_query_t,
    src: *mut z_moved_closure_query_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).context = (*src)._this.context;
    (*dst).call = (*src)._this.call;
    (*dst).drop = (*src)._this.drop;
    (*src)._this = z_owned_closure_query_t::null_value();
}

/// Drop an owned query closure that was never declared (pico
/// `z_closure_query_drop`): run the C `drop(context)` and null the struct.
#[no_mangle]
pub unsafe extern "C" fn z_closure_query_drop(closure: *mut z_moved_closure_query_t) {
    let _ = guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        let owned = &mut (*closure)._this;
        if let Some(dropfn) = owned.drop {
            dropfn(owned.context);
        }
        *owned = z_owned_closure_query_t::null_value();
        Z_OK
    });
}

// --- queryable options -----------------------------------------------------

/// Queryable options (pico `z_queryable_options_t`).
///
/// `{ bool complete; }` — the `allowed_origin` field exists only under
/// `Z_FEATURE_LOCAL_QUERYABLE`, which pico defaults to **0**
/// (`~/zenoh-pico/CMakeLists.txt:353`), so the default-config layout is this
/// one. Mirroring pico's api.c feature gates rather than its header is the rule
/// here: the header declares fields/ops unconditionally, the gates decide what a
/// default build actually has.
#[repr(C)]
pub struct z_queryable_options_t {
    pub complete: bool,
}

/// Fill default queryable options (pico `z_queryable_options_default`):
/// `complete = false`, the incomplete default.
#[no_mangle]
pub unsafe extern "C" fn z_queryable_options_default(options: *mut z_queryable_options_t) {
    if !options.is_null() {
        (*options).complete = false;
    }
}

/// Reply options (pico `z_query_reply_options_t`). `congestion_control` /
/// `priority` are carried for layout only — pico documents both "Deprecated:
/// ignored, taken from query" (`api/types.h:318-321`).
#[repr(C)]
pub struct z_query_reply_options_t {
    /// `z_moved_encoding_t*`. Opaque here: the encoding type family is a
    /// follow-up round, so a C program linking this library has no exported
    /// `z_encoding_*` to build one with and this is always null in practice.
    pub encoding: *mut c_void,
    pub congestion_control: z_congestion_control_t,
    pub priority: z_priority_t,
    /// `z_timestamp_t*` — opaque (the timestamp family is a follow-up round).
    pub timestamp: *mut c_void,
    pub is_express: bool,
    pub attachment: *mut z_moved_bytes_t,
}

/// Fill default reply options (pico `z_query_reply_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_options_default(options: *mut z_query_reply_options_t) {
    if options.is_null() {
        return;
    }
    (*options).encoding = std::ptr::null_mut();
    (*options).congestion_control = 0;
    (*options).priority = 5;
    (*options).timestamp = std::ptr::null_mut();
    (*options).is_express = false;
    (*options).attachment = std::ptr::null_mut();
}

/// Del-reply options (pico `z_query_reply_del_options_t`) — the reply options
/// without the encoding (a Del carries no payload to encode).
#[repr(C)]
pub struct z_query_reply_del_options_t {
    pub congestion_control: z_congestion_control_t,
    pub priority: z_priority_t,
    pub timestamp: *mut c_void,
    pub is_express: bool,
    pub attachment: *mut z_moved_bytes_t,
}

/// Fill default del-reply options (pico `z_query_reply_del_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_del_options_default(
    options: *mut z_query_reply_del_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).congestion_control = 0;
    (*options).priority = 5;
    (*options).timestamp = std::ptr::null_mut();
    (*options).is_express = false;
    (*options).attachment = std::ptr::null_mut();
}

/// Err-reply options (pico `z_query_reply_err_options_t`) — `{ encoding }`.
#[repr(C)]
pub struct z_query_reply_err_options_t {
    /// `z_moved_encoding_t*` — opaque; see [`z_query_reply_options_t::encoding`].
    pub encoding: *mut c_void,
}

/// Fill default err-reply options (pico `z_query_reply_err_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_err_options_default(
    options: *mut z_query_reply_err_options_t,
) {
    if !options.is_null() {
        (*options).encoding = std::ptr::null_mut();
    }
}

// --- queryable handle ------------------------------------------------------

/// Behind a `z_owned_queryable_t` handle: the C queryable's id in the session's
/// responder SSOT. Dropping it retracts the declaration — removing it from the
/// SSOT (so no future face replays it) and dropping every live face's wz
/// queryable, which emits each wire undeclare and releases the last closure
/// reference (→ the C `drop(context)`).
struct QueryableState {
    shared: Arc<SharedSession>,
    id: QblId,
    keyexpr: String,
    /// Cached `{ start, len }` over `keyexpr`, so `z_queryable_keyexpr` hands
    /// back a borrow of stable storage rather than of a temporary.
    loaned_keyexpr: z_loaned_keyexpr_t,
}

impl Drop for QueryableState {
    fn drop(&mut self) {
        self.shared.undeclare_queryable(self.id);
    }
}

/// Owned queryable (pico `z_owned_queryable_t`). Handle model, as publisher /
/// subscriber (see [`crate::abi`]).
#[repr(C)]
pub struct z_owned_queryable_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Loaned queryable (pico `z_loaned_queryable_t`).
#[repr(C)]
pub struct z_loaned_queryable_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Moved queryable (pico `z_moved_queryable_t`).
#[repr(C)]
pub struct z_moved_queryable_t {
    pub(crate) _this: z_owned_queryable_t,
}

impl z_owned_queryable_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 3],
        }
    }
}

/// # Safety
/// `h` must be a live `Box::into_raw::<QueryableState>` pointer.
unsafe fn free_queryable(h: *mut c_void) {
    drop(Box::from_raw(h as *mut QueryableState));
}

impl_handle_ownership7!(
    z_owned_queryable_t,
    z_loaned_queryable_t,
    z_moved_queryable_t,
    free_queryable,
    z_internal_queryable_null,
    z_internal_queryable_check,
    z_queryable_loan,
    z_queryable_loan_mut,
    z_queryable_move,
    z_queryable_take,
    z_queryable_drop
);

// --- declare / undeclare ---------------------------------------------------

/// Shared body of `z_declare_queryable` / `z_declare_background_queryable`:
/// consume the moved closure, validate, and record the SSOT entry.
///
/// Returns the queryable id on success. The moved closure is consumed on EVERY
/// path (pico's contract): `CQueryClosure` owns the C `drop(context)` from the
/// moment it is built, so an early error drops it and frees the context.
unsafe fn declare_queryable_inner(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_query_t,
    options: *const z_queryable_options_t,
) -> Result<(Arc<SharedSession>, QblId, String), ZResult> {
    if callback.is_null() {
        return Err(Z_ERR_NULL);
    }
    let owned = &mut (*callback)._this;
    let cclosure = CQueryClosure::new(owned.context, owned.call, owned.drop);
    *owned = z_owned_closure_query_t::null_value();

    let state = match session_state(zs) {
        Some(s) => s,
        None => return Err(Z_ERR_NULL),
    };
    let ke = match keyexpr_str(keyexpr) {
        Some(k) => k.to_owned(),
        None => return Err(Z_ERR_INVALID),
    };
    // Reject a non-canonical / pico-unsafe keyexpr UP FRONT — the same
    // outbound gate `z_declare_subscriber` hoists, and for the same reason:
    // the registry declares best-effort per face, so a per-face reject would
    // be swallowed and the call would report `Z_OK` for a dead SSOT entry.
    if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
        return Err(Z_ERR_INVALID);
    }
    let complete = if options.is_null() {
        false
    } else {
        (*options).complete
    };
    let id = state
        .shared
        .declare_queryable(ke.clone(), complete, Arc::new(cclosure));
    Ok((state.shared.clone(), id, ke))
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

/// Declare a queryable (pico `z_declare_queryable`). Consumes the moved
/// closure.
#[no_mangle]
pub unsafe extern "C" fn z_declare_queryable(
    zs: *const z_loaned_session_t,
    queryable: *mut z_owned_queryable_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_query_t,
    options: *const z_queryable_options_t,
) -> ZResult {
    guarded(|| {
        if queryable.is_null() {
            return Z_ERR_NULL;
        }
        match declare_queryable_inner(zs, keyexpr, callback, options) {
            Ok((shared, id, ke)) => {
                let mut boxed = Box::new(QueryableState {
                    shared,
                    id,
                    keyexpr: ke,
                    loaned_keyexpr: z_loaned_keyexpr_t {
                        _start: std::ptr::null(),
                        _len: 0,
                    },
                });
                // Point the cached view at the boxed keyexpr's final address.
                boxed.loaned_keyexpr = z_loaned_keyexpr_t {
                    _start: boxed.keyexpr.as_ptr(),
                    _len: boxed.keyexpr.len(),
                };
                *queryable = z_owned_queryable_t {
                    handle: Box::into_raw(boxed) as *mut c_void,
                    _pad: [std::ptr::null_mut(); 3],
                };
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// Declare a background queryable (pico `z_declare_background_queryable`): the
/// declaration lives until the session is closed or dropped, with no handle
/// handed back.
///
/// The SSOT entry is simply never retracted by a handle drop — the registry
/// holds it (and so the C closure) until the session's `SharedSession` is
/// dropped, which is exactly pico's "until the corresponding session is closed
/// or dropped" contract.
#[no_mangle]
pub unsafe extern "C" fn z_declare_background_queryable(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_query_t,
    options: *const z_queryable_options_t,
) -> ZResult {
    guarded(
        || match declare_queryable_inner(zs, keyexpr, callback, options) {
            Ok(_) => Z_OK,
            Err(code) => code,
        },
    )
}

/// Undeclare a queryable (pico `z_undeclare_queryable`): drops every face's wz
/// queryable (undeclare on the wire) and the callback (→ C `drop(context)`).
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_queryable(queryable: *mut z_moved_queryable_t) -> ZResult {
    guarded(|| {
        if queryable.is_null() {
            return Z_OK;
        }
        let handle = (*queryable)._this.handle;
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut QueryableState));
            (*queryable)._this = z_owned_queryable_t::null_value();
        }
        Z_OK
    })
}

/// Borrow a queryable's keyexpr (pico `z_queryable_keyexpr`).
#[no_mangle]
pub unsafe extern "C" fn z_queryable_keyexpr(
    queryable: *const z_loaned_queryable_t,
) -> *const z_loaned_keyexpr_t {
    match handle_ref::<z_loaned_queryable_t, QueryableState>(queryable) {
        Some(state) => &state.loaned_keyexpr as *const z_loaned_keyexpr_t,
        None => std::ptr::null(),
    }
}

// --- loaned-query accessors ------------------------------------------------

/// Borrow the query's keyexpr (pico `z_query_keyexpr`).
#[no_mangle]
pub unsafe extern "C" fn z_query_keyexpr(
    query: *const z_loaned_query_t,
) -> *const z_loaned_keyexpr_t {
    match query_marshal(query) {
        Some(marshal) => &marshal.loaned_keyexpr as *const z_loaned_keyexpr_t,
        None => std::ptr::null(),
    }
}

/// Write the query's selector parameters into `parameters` as a view string
/// (pico `z_query_parameters`). A query with no parameters segment yields an
/// empty (not null) view, matching pico.
#[no_mangle]
pub unsafe extern "C" fn z_query_parameters(
    query: *const z_loaned_query_t,
    parameters: *mut z_view_string_t,
) {
    let _ = guarded(|| {
        if parameters.is_null() {
            return Z_OK;
        }
        let (start, len) = match query_marshal(query) {
            Some(marshal) => (marshal.parameters.as_ptr(), marshal.parameters.len()),
            None => (std::ptr::null(), 0),
        };
        (*parameters) = z_view_string_t {
            _start: start,
            _len: len,
            _pad: [0; 2],
        };
        Z_OK
    });
}

/// Borrow the query's value payload (pico `z_query_payload`). Null when the
/// query carries no value ext — pico's own contract for a payload-less query.
#[no_mangle]
pub unsafe extern "C" fn z_query_payload(
    query: *const z_loaned_query_t,
) -> *const z_loaned_bytes_t {
    match query_marshal(query) {
        Some(marshal) if marshal.has_payload => &marshal.loaned_payload as *const z_loaned_bytes_t,
        _ => std::ptr::null(),
    }
}

/// Borrow the query's attachment (pico `z_query_attachment`). Null when the
/// query carries no attachment ext.
#[no_mangle]
pub unsafe extern "C" fn z_query_attachment(
    query: *const z_loaned_query_t,
) -> *const z_loaned_bytes_t {
    match query_marshal(query) {
        Some(marshal) if marshal.has_attachment => {
            &marshal.loaned_attachment as *const z_loaned_bytes_t
        }
        _ => std::ptr::null(),
    }
}

// --- z_query_reply family --------------------------------------------------

/// Reply to a query (pico `z_query_reply`). Consumes the moved payload.
///
/// The reply is accumulated and emitted when the callback returns; see the
/// module doc for why that is observably identical to emitting inline.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply(
    query: *const z_loaned_query_t,
    keyexpr: *const z_loaned_keyexpr_t,
    payload: *mut z_moved_bytes_t,
    _options: *const z_query_reply_options_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved payload FIRST so it is freed on every path (pico's
        // "z_move consumes on all paths" contract).
        let buf = match crate::pubsub::take_moved_bytes(payload) {
            Some(b) => b,
            None => return Z_ERR_NULL,
        };
        let marshal = match query_marshal(query) {
            Some(m) => m,
            None => return Z_ERR_INVALID,
        };
        // A reply must be covered by the query the querier asked under (the
        // `reply ⊆ query` zenoh contract). pico lets the queryable pass any
        // keyexpr; wz's `reply_keyed` seam likewise does not re-check it, so
        // this forwards the caller's key verbatim.
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            // A null keyexpr means "reply under the query's own key".
            None => marshal.keyexpr.clone(),
        };
        marshal.push_reply(PendingReply::Put {
            keyexpr: ke,
            payload: buf,
        });
        Z_OK
    })
}

/// Reply to a query with a Del (pico `z_query_reply_del`).
///
/// NAMED DIVERGENCE (loud, not silent): wz's reply seam has no keyed-Del —
/// [`ReplyOut::reply_del`] takes no keyexpr and always emits under the
/// responder's bound (query) key, while pico's `z_query_reply_del` accepts an
/// arbitrary one. A `keyexpr` equal to the query's is therefore honoured; a
/// DIFFERENT one is unrepresentable and returns [`Z_ERR_INVALID`] rather than
/// silently replying under the wrong key. Closing this needs a `reply_keyed_del`
/// on the wz-session-core seam (and its codec arm) — an upstream round, tracked
/// in the ledger carry.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_del(
    query: *const z_loaned_query_t,
    keyexpr: *const z_loaned_keyexpr_t,
    _options: *const z_query_reply_del_options_t,
) -> ZResult {
    guarded(|| {
        let marshal = match query_marshal(query) {
            Some(m) => m,
            None => return Z_ERR_INVALID,
        };
        // A null keyexpr means "del under the query's own key".
        if let Some(ke) = keyexpr_str(keyexpr) {
            if ke != marshal.keyexpr {
                return Z_ERR_INVALID;
            }
        }
        marshal.push_reply(PendingReply::Del);
        Z_OK
    })
}

/// Reply to a query with an error (pico `z_query_reply_err`). Consumes the
/// moved payload.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_err(
    query: *const z_loaned_query_t,
    payload: *mut z_moved_bytes_t,
    _options: *const z_query_reply_err_options_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved payload FIRST (pico consume-on-all-paths contract).
        let buf = match crate::pubsub::take_moved_bytes(payload) {
            Some(b) => b,
            None => return Z_ERR_NULL,
        };
        let marshal = match query_marshal(query) {
            Some(m) => m,
            None => return Z_ERR_INVALID,
        };
        marshal.push_reply(PendingReply::Err { payload: buf });
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `QueryView` carrying a value payload + an attachment.
    struct FakeQuery {
        keyexpr: String,
        payload: Vec<u8>,
        attachment: Vec<u8>,
    }

    impl QueryView for FakeQuery {
        fn keyexpr(&self) -> &str {
            &self.keyexpr
        }
        fn parameters(&self) -> Option<&[u8]> {
            None
        }
        fn attachment(&self) -> Option<&[u8]> {
            Some(&self.attachment)
        }
        fn payload(&self) -> Option<&[u8]> {
            Some(&self.payload)
        }
        fn rid(&self) -> u64 {
            7
        }
    }

    /// The cached views must point at THIS marshal's own fields — the address
    /// invariant `bind` exists to establish.
    ///
    /// Regression gate for the bug an earlier cut shipped: `QueryMarshal::new`
    /// bound `loaned_payload.handle` to `&self.payload` — the address of the
    /// `Vec` STRUCT — and then returned `Self` BY VALUE, so the handle pointed
    /// into `new`'s dead frame and `z_query_payload` handed C a `Vec`
    /// reconstructed from freed stack. `loaned_keyexpr` hid it (`String::as_ptr`
    /// is the heap buffer, which a move does not relocate) and the wire test
    /// reads only the keyexpr, so the suite stayed green over UB.
    ///
    /// This asserts the ADDRESS, not the bytes, and that distinction is the
    /// whole point: reading a dangling handle is UB that routinely *appears* to
    /// work — a read-back assertion was tried first and passed even with the bug
    /// deliberately restored, because the dead frame still held the old `Vec`.
    /// The address invariant is deterministic and fails the instant `bind` runs
    /// anywhere but the final location.
    #[test]
    fn bind_points_the_cached_views_at_this_marshals_own_fields() {
        let view = FakeQuery {
            keyexpr: "demo/q".to_owned(),
            payload: b"value-payload".to_vec(),
            attachment: b"att".to_vec(),
        };
        // Exactly the shape `make_queryable_callback` uses: construct, move out
        // of `new`, then bind at the final address.
        let mut marshal = QueryMarshal::new(&view);
        marshal.bind();

        assert_eq!(
            marshal.loaned_payload.handle as usize, &marshal.payload as *const Vec<u8> as usize,
            "the cached payload view must address THIS marshal's Vec, not a moved-from copy's"
        );
        assert_eq!(
            marshal.loaned_attachment.handle as usize,
            &marshal.attachment as *const Vec<u8> as usize,
            "the cached attachment view must address THIS marshal's Vec"
        );
        assert_eq!(
            marshal.loaned_keyexpr._start as usize,
            marshal.keyexpr.as_ptr() as usize,
            "the cached keyexpr view must address THIS marshal's string buffer"
        );

        // The accessors built on those views resolve to the query's bytes.
        let query = &marshal as *const QueryMarshal as *const z_loaned_query_t;
        unsafe {
            let buf = handle_ref::<z_loaned_bytes_t, Vec<u8>>(z_query_payload(query))
                .expect("the cached payload view must resolve");
            assert_eq!(buf.as_slice(), b"value-payload");
            let buf = handle_ref::<z_loaned_bytes_t, Vec<u8>>(z_query_attachment(query))
                .expect("the cached attachment view must resolve");
            assert_eq!(buf.as_slice(), b"att");
            assert_eq!(
                crate::keyexpr::keyexpr_str(z_query_keyexpr(query)),
                Some("demo/q")
            );
        }
    }
}

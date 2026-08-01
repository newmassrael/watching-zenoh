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
//! Two accessors are withheld on the same principle, each because it returns a
//! type family this round does not build — a missing symbol is a link error,
//! while a stub returning null would be a silent lie:
//! - `z_query_encoding` → `z_loaned_encoding_t` (the encoding family).
//! - `z_query_source_info` → `z_source_info_t` (the source-info family).
//!
//! That is the COMPLETE withheld set for a DEFAULT pico build, which is the
//! configuration this crate's ABI targets. `z_queryable_id` looks like a third
//! but is not: it is `#if defined(Z_FEATURE_UNSTABLE_API)`
//! (`primitives.h:2884-2886`) and that flag defaults to 0
//! (`~/zenoh-pico/CMakeLists.txt:316`), so a default build has no such symbol to
//! match. Everything else in pico's default queryable surface is exported —
//! including `z_query_accepts_replies`, which is the `_anyke` accessor
//! [`z_query_reply`]'s coverage gate turns on.
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

use wz_runtime_tokio::keyexpr_match;
use wz_runtime_tokio::query_sink::{QueryView, ReplyOut};

use crate::abi::{
    handle_ref, impl_handle_ownership7, z_loaned_bytes_t, z_loaned_keyexpr_t, z_moved_bytes_t,
    z_view_string_t,
};
use crate::ffi::{guarded, CClosure as FfiClosure};
use crate::keyexpr::keyexpr_str;
use crate::result::{ZResult, Z_ERR_INVALID, Z_ERR_KEYEXPR_NOT_MATCH, Z_ERR_NULL, Z_OK};
use crate::session::{session_state, z_loaned_session_t};
use wz_capi_core::faces::{QblId, SharedSession};

// --- pico enum-typed option fields -----------------------------------------
//
// pico's `z_congestion_control_t` / `z_priority_t` are plain C enums, so each
// occupies an `int` in the option structs below. Both are documented
// "Deprecated: ignored, taken from query" on the reply options
// (`~/zenoh-pico/include/zenoh-pico/api/types.h:318-321`), so they are carried
// for layout only.
pub type z_congestion_control_t = c_int;
pub type z_priority_t = c_int;

/// pico `Z_CONGESTION_CONTROL_BLOCK` (`api/constants.h:216`) — the value pico's
/// `z_query_reply_options_default` writes (`src/api/api.c:2118,2181`). NOT 0:
/// that is `Z_CONGESTION_CONTROL_DROP`, a different documented default.
pub(crate) const Z_CONGESTION_CONTROL_BLOCK: z_congestion_control_t = 1;

/// pico `Z_PRIORITY_DEFAULT` = `Z_PRIORITY_DATA` = 5 (`api/constants.h:247-250`).
pub(crate) const Z_PRIORITY_DEFAULT: z_priority_t = 5;

// --- opaque loaned query ---------------------------------------------------

/// Opaque loaned query (pico `z_loaned_query_t`). The C callback only holds a
/// pointer to it and passes it back to the accessors / `z_query_reply`, so this
/// stays opaque rather than reproducing pico's concrete `_z_query_t` layout —
/// the same model `z_loaned_sample_t` uses.
#[repr(C)]
pub struct z_loaned_query_t {
    _opaque: [u8; 0],
}

/// pico's `_anyke` selector-parameter key (`Z_SELECTOR_QUERY_MATCH`,
/// `~/zenoh-pico/include/zenoh-pico/api/constants.h:18`).
pub(crate) const ANYKE_PARAM: &[u8] = b"_anyke";

/// pico's selector-parameter list separator (`_Z_QUERY_PARAMS_LIST_SEPARATOR`,
/// `~/zenoh-pico/include/zenoh-pico/utils/query_params.h`).
pub(crate) const PARAM_SEPARATOR: u8 = b';';

/// Whether a query's selector parameters carry the `_anyke` key — pico's
/// [`_z_parameters_has_anyke`](https://github.com/eclipse-zenoh/zenoh-pico)
/// (`src/utils/query_params.c:46-70`), ported chunk-boundary rules and all.
///
/// This is how the RESPONDER learns `_anyke`: it is not a wire field but a
/// SELECTOR PARAMETER. The querier's `accept_replies = Z_REPLY_KEYEXPR_ANY`
/// makes the sender append `_anyke` to the parameter list
/// (`src/protocol/codec/message.c:399-423`), and on reception `_implicit_anyke`
/// is unconditionally false — pico's own comment says the flag "is signaled by
/// the presence of the _anyke key in the parameters list, which is parsed
/// later" (`codec/message.c:488-490`). So the responder-side derivation
/// reduces to exactly this parse:
/// `dst->_anyke = implicit_anyke || _z_parameters_has_anyke(...)`
/// (`include/zenoh-pico/net/query.h:104`) with `implicit_anyke == false`.
///
/// The boundary checks are load-bearing and are why this is a real parse rather
/// than a substring search: `_anyke` must start the list or follow a `;`, and
/// must end the list or precede a `;`. Without them a parameter such as
/// `no_anyke` or `_anykey=1` would be read as the flag.
pub(crate) fn parameters_has_anyke(parameters: &[u8]) -> bool {
    let mut start = 0usize;
    while start <= parameters.len() {
        let Some(offset) = parameters[start..]
            .windows(ANYKE_PARAM.len())
            .position(|window| window == ANYKE_PARAM)
        else {
            return false;
        };
        let pos = start + offset;
        let end = pos + ANYKE_PARAM.len();
        let left_ok = pos == 0 || parameters[pos - 1] == PARAM_SEPARATOR;
        let right_ok = end == parameters.len() || parameters[end] == PARAM_SEPARATOR;
        if left_ok && right_ok {
            return true;
        }
        start = end + 1;
    }
    false
}

/// Whether `reply` is covered by the query — zenoh's `reply ⊆ query` contract as
/// pico enforces it: `!query->_anyke && !_z_declared_keyexpr_intersects(...)`
/// → `_Z_ERR_KEYEXPR_NOT_MATCH` (`~/zenoh-pico/src/net/primitives.c:437-440`).
///
/// INTERSECTION, never string equality. The query keyexpr a queryable is asked
/// under is routinely a PATTERN (a queryable declared on `a/**` sees the
/// querier's `a/**`), while its replies carry CONCRETE keys — so equality would
/// reject the ordinary wildcard case, not an edge case. Routed through the one
/// matching SSOT ([`wz_runtime_tokio::keyexpr_match`]) rather than re-derived.
pub(crate) fn reply_keyexpr_is_covered(query_keyexpr: &str, reply: &str, anyke: bool) -> bool {
    if anyke {
        return true;
    }
    let query_chunks: Vec<&str> = query_keyexpr.split('/').collect();
    let reply_chunks: Vec<&str> = reply.split('/').collect();
    keyexpr_match::keyexpr_intersect_patterns(&query_chunks, &reply_chunks)
}

/// One reply the C callback asked for, held until the callback returns and the
/// batch is flushed into the wz [`ReplyOut`].
enum PendingReply {
    /// `z_query_reply` — a Put-form reply under an explicit keyexpr.
    Put {
        keyexpr: String,
        payload: Vec<u8>,
        attachment: Option<Vec<u8>>,
    },
    /// `z_query_reply_del` — a Del-form reply under an explicit keyexpr.
    Del { keyexpr: String },
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
    /// pico's `_anyke`: whether this query accepts replies under ANY key rather
    /// than only keys it covers. Derived from `parameters` at marshal time (see
    /// [`parameters_has_anyke`]) — the same derivation pico does, and the gate
    /// `z_query_reply` consults.
    anyke: bool,
    /// The query's value payload, EMPTY when the query carried no value ext.
    ///
    /// There is deliberately no `has_payload` companion. pico's
    /// `z_query_payload` is `return &..->_value.payload` — it hands back a
    /// pointer unconditionally and lets an empty payload speak for itself
    /// (`vendor/zenoh-pico/src/api/api.c:476`), and the same is true of
    /// `z_query_attachment` (:472). Carrying a presence flag here invites the
    /// accessor to return NULL for absence, which is the one thing a pico
    /// program cannot survive; see the accessors' own docstrings.
    payload: Vec<u8>,
    /// The query's attachment, EMPTY when absent. Same no-presence-flag rule as
    /// [`Self::payload`].
    attachment: Vec<u8>,
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
        let parameters = view.parameters().map(<[u8]>::to_vec).unwrap_or_default();
        Self {
            keyexpr: view.keyexpr().to_owned(),
            anyke: parameters_has_anyke(&parameters),
            parameters,
            // Absence collapses to EMPTY here, not to a flag: the accessors
            // must hand C a pointer either way (see the field docs).
            payload: view.payload().map(<[u8]>::to_vec).unwrap_or_default(),
            attachment: view.attachment().map(<[u8]>::to_vec).unwrap_or_default(),
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
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
        self.loaned_keyexpr =
            z_loaned_keyexpr_t::borrowed(self.keyexpr.as_ptr(), self.keyexpr.len());
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
                PendingReply::Put {
                    keyexpr,
                    payload,
                    attachment,
                } => match attachment {
                    // The attachment rides the reply only through the keyed
                    // ATTACHED seam; `reply_keyed` has no slot for it.
                    Some(att) => out.reply_keyed_attached(&keyexpr, &payload, None, &att),
                    None => out.reply_keyed(&keyexpr, &payload),
                },
                PendingReply::Del { keyexpr } => out.reply_keyed_del(&keyexpr),
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
/// queryable plane's instantiation of the shared [`crate::ffi::CClosure`]
/// mechanism. Its `Drop` invokes the C `drop(context)` exactly once, when the
/// last face's callback and the registry's SSOT entry have both released it.
pub(crate) type CQueryClosure = FfiClosure<z_closure_query_callback_t>;

// SAFETY: the responder plane's own argument, written here rather than granted
// by a blanket impl on the generic (see `crate::ffi::CClosure`).
//
// Sharing one queryable's `CQueryClosure` across a per-face callback needs
// `Sync` (so `Arc<CQueryClosure>`, and each callback, is `Send`). Sharing
// `&CQueryClosure` is sound because `call` is only ever invoked from the
// session's single drive task: every face of a session is driven on ONE task,
// and the queryable handler fires from that task's inbound dispatch drain.
//
// It is load-bearing that the C application thread never invokes `call`, and
// what makes that MECHANICAL rather than a promise is that this crate declares
// every queryable `Locality::Remote` (`faces::queryable_options`). A Remote
// queryable is unreachable from `Session::query`'s in-process fan
// (`session/mod.rs:1976`, gated on the queryable registry's locality), so no
// `z_get` on the C thread — whatever locality IT chooses — can run this handler
// there. Relying instead on the get side passing `Locality::Remote` would be a
// promise the next round could silently break; `Any::allows_local()` is true
// (`wz-session-core/src/locality.rs:70-72`), so a default-locality get would
// otherwise drain a local queryable job on the C thread while a drive thread ran
// `call` on another face — two `call(context)`s at once on one C context, the
// unsound-`Sync` bug R311y288 already fixed once on the publish plane.
//
// `drop` runs only when the last `Arc` is released, which cannot overlap a live
// `call` (a running callback holds a reference).
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
    (*options).congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    (*options).priority = Z_PRIORITY_DEFAULT;
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
    (*options).congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    (*options).priority = Z_PRIORITY_DEFAULT;
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
    let id = state.shared.declare_queryable(ke.clone(), complete, {
        // R311y498 — see the pubsub/liveliness twins: the shim mints, the
        // registry calls the factory per face, the C drop(context) is unmoved.
        let closure = Arc::new(cclosure);
        Arc::new(move || Box::new(make_queryable_callback(closure.clone())) as Box<_>)
    });
    Ok((state.shared.clone(), id, ke))
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
                    loaned_keyexpr: z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
                });
                // Point the cached view at the boxed keyexpr's final address.
                boxed.loaned_keyexpr =
                    z_loaned_keyexpr_t::borrowed(boxed.keyexpr.as_ptr(), boxed.keyexpr.len());
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

/// Borrow the query's value payload (pico `z_query_payload`). A payload-less
/// query yields a valid pointer to an EMPTY payload, never null; null is
/// reserved for an invalid `query` pointer.
///
/// This is pico's contract, read off its implementation:
/// `z_query_payload` is `return &_Z_RC_IN_VAL(query)->_value.payload`
/// (`vendor/zenoh-pico/src/api/api.c:476`) — an unconditional address-of, with
/// no presence check anywhere. The neighbouring `z_query_source_info` (:478-481)
/// DOES do `_z_source_info_check(info) ? info : NULL`, so pico's own getters are
/// asymmetric on purpose, and reading the shape off the wrong sibling is how
/// this diverged.
///
/// The divergence was not cosmetic. Real pico programs call this getter
/// unconditionally — `examples/unix/c11/z_queryable.c` does
/// `z_bytes_to_string(z_query_payload(query), &payload_string)` and only THEN
/// tests `z_string_len(...) > 0`. Returning null made `z_bytes_to_string` fail,
/// which leaves the caller's stack-allocated `z_owned_string_t` UNINITIALIZED,
/// and the very next line loans it: the upstream queryable example aborted on
/// a garbage handle the moment a real `z_get` reached it. An absent payload is
/// an empty payload, and the C side must be able to say so without a crash.
#[no_mangle]
pub unsafe extern "C" fn z_query_payload(
    query: *const z_loaned_query_t,
) -> *const z_loaned_bytes_t {
    match query_marshal(query) {
        Some(marshal) => &marshal.loaned_payload as *const z_loaned_bytes_t,
        None => std::ptr::null(),
    }
}

/// pico `z_reply_keyexpr_t` (`api/constants.h:288-290`): the reply-keyexpr
/// policy a query accepts.
pub type z_reply_keyexpr_t = c_int;
/// pico `Z_REPLY_KEYEXPR_ANY` — accept replies on any key (`constants.h:289`).
pub const Z_REPLY_KEYEXPR_ANY: z_reply_keyexpr_t = 0;
/// pico `Z_REPLY_KEYEXPR_MATCHING_QUERY` — accept only replies whose key
/// intersects the query's (`constants.h:290`).
pub const Z_REPLY_KEYEXPR_MATCHING_QUERY: z_reply_keyexpr_t = 1;

/// Which replies this query accepts (pico `z_query_accepts_replies`,
/// `src/api/api.c:469`): `_anyke ? ANY : MATCHING_QUERY`.
///
/// This is the accessor for the very flag [`z_query_reply`] gates on, so a C
/// queryable can ask the same question the library asks before it rejects a
/// reply with [`Z_ERR_KEYEXPR_NOT_MATCH`]. A null / spent query reports
/// `MATCHING_QUERY`, the conservative answer (pico would dereference and
/// crash).
#[no_mangle]
pub unsafe extern "C" fn z_query_accepts_replies(
    query: *const z_loaned_query_t,
) -> z_reply_keyexpr_t {
    crate::ffi::guard_val(Z_REPLY_KEYEXPR_MATCHING_QUERY, || {
        match query_marshal(query) {
            Some(marshal) if marshal.anyke => Z_REPLY_KEYEXPR_ANY,
            _ => Z_REPLY_KEYEXPR_MATCHING_QUERY,
        }
    })
}

/// Borrow the query's attachment (pico `z_query_attachment`). An attachment-less
/// query yields a valid pointer to an EMPTY attachment, never null; null is
/// reserved for an invalid `query` pointer.
///
/// Same contract and same reasoning as [`z_query_payload`]: pico's getter is
/// `return &_Z_RC_IN_VAL(query)->_attachment` with no presence check
/// (`vendor/zenoh-pico/src/api/api.c:472`). Fixed together with its sibling
/// rather than only the one a running example happened to crash on — the two
/// had the identical shape, so a caller that reads the attachment
/// unconditionally would have hit the identical uninitialized-owned-struct
/// abort.
#[no_mangle]
pub unsafe extern "C" fn z_query_attachment(
    query: *const z_loaned_query_t,
) -> *const z_loaned_bytes_t {
    match query_marshal(query) {
        Some(marshal) => &marshal.loaned_attachment as *const z_loaned_bytes_t,
        None => std::ptr::null(),
    }
}

// --- z_query_reply family --------------------------------------------------

/// Reply to a query (pico `z_query_reply`). Consumes the moved payload AND the
/// moved `options->attachment`.
///
/// Enforces zenoh's `reply ⊆ query` contract exactly as pico does — see
/// [`reply_keyexpr_is_covered`]. The reply is accumulated and emitted when the
/// callback returns; see the module doc for why that is observably identical to
/// emitting inline.
///
/// Of `options`, `attachment` is honoured; `encoding` and `timestamp` are
/// unreachable (opaque, with no exported constructor — see
/// [`z_query_reply_options_t`]); `congestion_control` / `priority` are documented
/// ignored by pico itself. `is_express` is a NAMED DIVERGENCE: wz's [`ReplyOut`]
/// has no express arm on any reply form, so the flag cannot be honoured and is
/// dropped. It is a batching hint with no effect on delivery or content.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply(
    query: *const z_loaned_query_t,
    keyexpr: *const z_loaned_keyexpr_t,
    payload: *mut z_moved_bytes_t,
    options: *const z_query_reply_options_t,
) -> ZResult {
    guarded(|| {
        // Consume BOTH moved arguments FIRST so they are freed on every path
        // (pico's "z_move consumes on all paths" contract). The attachment is a
        // moved `z_bytes` like the payload, and `z_bytes_*` IS exported — so a C
        // program can build one, and failing to take it here would leak it.
        let buf = match crate::pubsub::take_moved_bytes(payload) {
            Some(b) => b,
            None => return Z_ERR_NULL,
        };
        let attachment = if options.is_null() {
            None
        } else {
            crate::pubsub::take_moved_bytes((*options).attachment)
        };
        let marshal = match query_marshal(query) {
            Some(m) => m,
            None => return Z_ERR_INVALID,
        };
        // pico dereferences `keyexpr` unconditionally (`_z_send_reply` passes it
        // straight into `_z_declared_keyexpr_intersects`), so a null there is a
        // caller bug that SEGFAULTS pico. Report it instead of inventing a
        // fallback: silently substituting the query's own key would hide the bug
        // and claim a pico semantic that does not exist.
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_NULL,
        };
        if !reply_keyexpr_is_covered(&marshal.keyexpr, &ke, marshal.anyke) {
            return Z_ERR_KEYEXPR_NOT_MATCH;
        }
        marshal.push_reply(PendingReply::Put {
            keyexpr: ke,
            payload: buf,
            attachment,
        });
        Z_OK
    })
}

/// Reply to a query with a Del (pico `z_query_reply_del`). Consumes the moved
/// `options->attachment`.
///
/// Takes an arbitrary reply keyexpr, as pico's does, and enforces the same
/// `reply ⊆ query` rule as [`z_query_reply`]. An earlier cut of this round
/// accepted only a keyexpr STRING-EQUAL to the query's and rejected the rest as
/// a "named divergence" — that was wrong twice over: string equality against a
/// query key that is routinely a PATTERN rejects the ordinary wildcard case, and
/// the seam it claimed to be blocked on ([`ReplyOut::reply_keyed_del`]) was a
/// ten-line addition to the Put arm's existing keyed family, not a missing
/// concept. It was a cost-deferral wearing a divergence's clothes; the seam is
/// now built, so there is nothing to diverge about.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_del(
    query: *const z_loaned_query_t,
    keyexpr: *const z_loaned_keyexpr_t,
    options: *const z_query_reply_del_options_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved attachment on every path (see `z_query_reply`).
        // A Del reply carries no attachment through the wz seam, so this is a
        // take-and-drop: the C side's contract is still honoured (its `z_bytes`
        // is freed and its source nulled) and nothing leaks. The dropped
        // attachment is the same named gap as the Put arm's `is_express`.
        let attachment = if options.is_null() {
            None
        } else {
            crate::pubsub::take_moved_bytes((*options).attachment)
        };
        drop(attachment);
        let marshal = match query_marshal(query) {
            Some(m) => m,
            None => return Z_ERR_INVALID,
        };
        // Null is a caller bug that segfaults pico — reported, not substituted
        // (see `z_query_reply`).
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_NULL,
        };
        if !reply_keyexpr_is_covered(&marshal.keyexpr, &ke, marshal.anyke) {
            return Z_ERR_KEYEXPR_NOT_MATCH;
        }
        marshal.push_reply(PendingReply::Del { keyexpr: ke });
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
    /// pico's `_anyke` is a SELECTOR PARAMETER, not a wire field, and the
    /// boundary rules are what make it a parse rather than a substring search.
    /// Ported from `~/zenoh-pico/src/utils/query_params.c:46-70`.
    #[test]
    fn anyke_parses_with_picos_parameter_boundary_rules() {
        assert!(parameters_has_anyke(b"_anyke"));
        assert!(parameters_has_anyke(b"a=1;_anyke"));
        assert!(parameters_has_anyke(b"_anyke;a=1"));
        assert!(parameters_has_anyke(b"a=1;_anyke;b=2"));
        assert!(!parameters_has_anyke(b""));
        assert!(!parameters_has_anyke(b"a=1"));
        // The boundary rules earn their keep here: each of these CONTAINS
        // "_anyke" and must NOT be read as the flag.
        assert!(!parameters_has_anyke(b"no_anyke"));
        assert!(!parameters_has_anyke(b"_anykey=1"));
        assert!(!parameters_has_anyke(b"a=1;xx_anyke_yy;b=2"));
        // ...but a real flag AFTER a decoy is still found (the scan continues).
        assert!(parameters_has_anyke(b"_anykey=1;_anyke"));
    }

    /// The `reply ⊆ query` gate is an INTERSECTION, so a wildcard query admits
    /// concrete replies — the ordinary case for a wildcard queryable, and the
    /// one an earlier string-equality cut of this round rejected.
    #[test]
    fn reply_coverage_is_intersection_not_string_equality() {
        // The case string equality got wrong: query is a PATTERN, reply concrete.
        assert!(reply_keyexpr_is_covered("a/**", "a/b", false));
        assert!(reply_keyexpr_is_covered("a/*", "a/b", false));
        assert!(reply_keyexpr_is_covered("a/b", "a/b", false));
        // Genuinely disjoint replies are rejected...
        assert!(!reply_keyexpr_is_covered("a/**", "z/b", false));
        assert!(!reply_keyexpr_is_covered("a/b", "a/c", false));
        // ...unless the querier said it accepts any key (`_anyke`), which is
        // exactly pico's `!query->_anyke && !intersects` short-circuit.
        assert!(reply_keyexpr_is_covered("a/**", "z/b", true));
        assert!(reply_keyexpr_is_covered("a/b", "a/c", true));
    }

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

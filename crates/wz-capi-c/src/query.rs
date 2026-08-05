// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The QUERYABLE plane: the query closure the C side builds, the declaration it
//! hands that closure to, and the borrowed query a handler answers through.
//!
//! ## One C queryable is N wz queryables
//!
//! Same registry story as [`crate::sub`]: a zenoh-c session is "one session,
//! many peers" while a wz unicast `Session` is one peer, so the declaration
//! lands in [`wz_capi_core`](wz_capi_core)'s SSOT and is replayed onto each face
//! as it comes up. Declare-before-peer therefore works here too.
//!
//! ## A query may ESCAPE its dispatch, and that is what makes this plane hard
//!
//! `z_queryable_with_channels.c` declares its queryable with a FIFO channel and
//! answers from `main`, arbitrarily later than the dispatch that delivered the
//! query. Two things must survive that escape:
//!
//! - the ability to EMIT a reply, which needs the face's session;
//! - the `ResponseFinal`, which must NOT go out until the last holder drops —
//!   a querier that sees the final considers the query answered and stops
//!   listening, so an early one silently truncates the replies.
//!
//! [`DeferredResponder`] carries both. The HOLD is taken by the dispatch after
//! the callback returns rather than inside the escape, because a hold is only
//! effective if it is visible to the terminator job the same drain batch staged,
//! and counting escapes after the callback is what keeps that ordering argument
//! in one place. Escapes are COUNTED, not flagged: a callback that pushes the
//! same query into two channels takes two holds and will see two responder
//! drops.

use std::cell::{Cell, UnsafeCell};
use std::ffi::{c_int, c_void};
use std::sync::Arc;

use wz_runtime_tokio::keyexpr_match;
use wz_runtime_tokio::query::{QueryReply, QueryResponder};
use wz_runtime_tokio::query_sink::{QueryView, ReplyOut};
use wz_runtime_tokio::session::TokioSession;

use crate::abi::{
    z_closure_drop_callback_t, z_closure_query_callback_t, z_loaned_bytes_t, z_loaned_keyexpr_t,
    z_loaned_query_t, z_loaned_queryable_t, z_loaned_session_t, z_moved_bytes_t,
    z_moved_closure_query_t, z_moved_query_t, z_moved_queryable_t, z_owned_closure_query_t,
    z_owned_query_t, z_owned_queryable_t, z_view_string_t, Handle,
};
use crate::bytes::BytesState;
use crate::ffi::{guard_val, guarded, CClosure as FfiClosure};
use crate::keyexpr::{keyexpr_str, KeyexprState};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::session::session_state;
use crate::string::view_string_over;

use wz_capi_core::faces::{QblId, SharedSession};

/// The Rust-side wrapper a queryable's per-face callbacks share.
pub(crate) type CQueryClosure = FfiClosure<z_closure_query_callback_t>;

// SAFETY: the same argument as `crate::sub`'s, for the same reason: one
// queryable's `CQueryClosure` is shared across per-face callbacks, so it must be
// `Sync` for each callback to be `Send`. `call` runs only on the session's
// single drive task (every face of a session is driven on one task, and inbound
// dispatch is its only caller), and `drop` runs when the last `Arc` is released,
// which cannot overlap a live `call` because a running callback holds a
// reference.
unsafe impl Sync for CQueryClosure {}

/// One reply the C callback asked for, held until it can be flushed.
enum PendingReply {
    /// `z_query_reply` — a Put-form reply under an explicit keyexpr.
    Put {
        keyexpr: String,
        payload: Vec<u8>,
        attachment: Option<Vec<u8>>,
    },
}

/// The wire seam an ESCAPED query replies through.
///
/// Holds the face's session so a reply issued long after the dispatch still
/// reaches the right peer, and releases the `ResponseFinal` hold on drop — which
/// is what makes "the query is answered when the C side drops it" true.
struct DeferredResponder {
    session: TokioSession,
    rid: u64,
}

impl DeferredResponder {
    /// Emit one reply NOW, through the same [`QueryResponder`] path the
    /// in-dispatch flush uses, so the deferred and immediate legs cannot drift.
    fn emit(&self, query_keyexpr: &str, reply: PendingReply) {
        let mut replies: Vec<QueryReply> = Vec::new();
        {
            let mut responder =
                QueryResponder::new(self.rid, query_keyexpr.to_owned(), &mut replies);
            let mut out: &mut dyn ReplyOut = &mut responder;
            flush_one(&mut out, reply);
        }
        for reply in replies.drain(..) {
            if let Ok(response) = reply.into_response() {
                self.session.actions().send_response(response);
            }
        }
    }
}

impl Drop for DeferredResponder {
    fn drop(&mut self) {
        // The terminator this escape has been holding open. Dropping the query
        // is what sends the `ResponseFinal`.
        self.session.release_response_final(self.rid);
    }
}

/// Route ONE accumulated reply into a [`ReplyOut`]. Shared by the in-dispatch
/// flush and the deferred emit so the two cannot answer differently.
fn flush_one(out: &mut &mut dyn ReplyOut, reply: PendingReply) {
    match reply {
        PendingReply::Put {
            keyexpr,
            payload,
            attachment,
        } => match attachment {
            Some(att) => out.reply_keyed_attached(&keyexpr, &payload, None, &att),
            None => out.reply_keyed(&keyexpr, &payload),
        },
    }
}

/// Whether `reply` is covered by the query — zenoh's `reply ⊆ query` contract.
///
/// INTERSECTION, never string equality. The keyexpr a queryable is asked under
/// is routinely a PATTERN while its replies carry CONCRETE keys, so equality
/// would reject the ordinary wildcard case rather than an edge case. Routed
/// through the one matching SSOT ([`keyexpr_match`]) rather than re-derived, and
/// shared with the RECEIVE gate in [`crate::get`] so the two halves agree.
pub(crate) fn reply_keyexpr_is_covered(query_keyexpr: &str, reply: &str, anyke: bool) -> bool {
    if anyke {
        return true;
    }
    let query_chunks: Vec<&str> = query_keyexpr.split('/').collect();
    let reply_chunks: Vec<&str> = reply.split('/').collect();
    keyexpr_match::keyexpr_intersect_patterns(&query_chunks, &reply_chunks)
}

/// Whether the selector asks for replies under ANY key (`_anyke`).
pub(crate) fn parameters_has_anyke(parameters: &[u8]) -> bool {
    std::str::from_utf8(parameters).is_ok_and(|text| {
        text.split('&')
            .any(|field| field == "_anyke" || field.starts_with("_anyke="))
    })
}

/// The owned marshal behind a borrowed `z_loaned_query_t`.
///
/// Owns copies of everything the accessors read, so it outlives the wz
/// [`QueryView`] borrow, and accumulates the replies the callback asks for.
pub(crate) struct QueryMarshal {
    keyexpr: String,
    parameters: Vec<u8>,
    anyke: bool,
    /// The query's VALUE payload, `None` when it carried no value ext.
    ///
    /// An `Option`, unlike the pico ABI's, and that is upstream's own contract
    /// rather than a preference: `z_queryable.c` writes
    /// `if (payload != NULL && z_bytes_len(payload) > 0)`, so a NULL is a shape
    /// the program is written to see. Handing back an empty-but-present blob
    /// would take the wrong branch.
    payload: Option<BytesState>,
    attachment: Option<BytesState>,
    keyexpr_state: KeyexprState,
    loaned_keyexpr: z_loaned_keyexpr_t,
    loaned_payload: z_loaned_bytes_t,
    loaned_attachment: z_loaned_bytes_t,
    /// The request id this query answers — the correlator a deferred reply and
    /// the terminator both need.
    rid: u64,
    /// The FACE's session, on a marshal the dispatch built. `None` on one built
    /// outside a dispatch, which is exactly the case that cannot be escaped.
    session: Option<TokioSession>,
    /// How many times this BORROWED marshal has been escaped, read back by the
    /// dispatch after the callback returns.
    escapes: Cell<u32>,
    /// Present only on an ESCAPED marshal.
    deferred: Option<DeferredResponder>,
    /// Reply accumulator.
    ///
    /// `UnsafeCell` because the accessors receive `*const z_loaned_query_t` and
    /// must append. The soundness anchor is upstream's callback contract: one
    /// query's callback — and any `z_query_reply` on its loaned query — runs on
    /// the session's single drive task, so no aliasing borrow exists while it
    /// runs.
    replies: UnsafeCell<Vec<PendingReply>>,
}

impl QueryMarshal {
    /// Build the marshal with its cached views still UNBOUND. [`Self::bind`]
    /// must run once the value sits at its final address — see
    /// [`crate::sample::SampleMarshal::bind`] for why that split is
    /// load-bearing.
    fn new(view: &dyn QueryView) -> Self {
        let parameters = view.parameters().map(<[u8]>::to_vec).unwrap_or_default();
        let keyexpr = view.keyexpr().to_owned();
        Self {
            anyke: parameters_has_anyke(&parameters),
            parameters,
            payload: view.payload().map(|p| BytesState::whole(p.to_vec())),
            attachment: view.attachment().map(|a| BytesState::whole(a.to_vec())),
            keyexpr_state: KeyexprState {
                keyexpr: keyexpr.clone(),
            },
            keyexpr,
            loaned_keyexpr: z_loaned_keyexpr_t::null_value(),
            loaned_payload: z_loaned_bytes_t::null_value(),
            loaned_attachment: z_loaned_bytes_t::null_value(),
            rid: view.rid(),
            session: None,
            escapes: Cell::new(0),
            deferred: None,
            replies: UnsafeCell::new(Vec::new()),
        }
    }

    /// Point every cached view at this marshal's own fields.
    fn bind(&mut self) {
        self.loaned_keyexpr = z_loaned_keyexpr_t::from_handle(
            &self.keyexpr_state as *const KeyexprState as *mut c_void,
        );
        self.loaned_payload = match self.payload.as_ref() {
            Some(state) => z_loaned_bytes_t::from_handle(state as *const BytesState as *mut c_void),
            None => z_loaned_bytes_t::null_value(),
        };
        self.loaned_attachment = match self.attachment.as_ref() {
            Some(state) => z_loaned_bytes_t::from_handle(state as *const BytesState as *mut c_void),
            None => z_loaned_bytes_t::null_value(),
        };
    }

    /// Bind the FACE's session, so this marshal can be escaped. Called only by
    /// the dispatch; a marshal without it is un-escapable by construction.
    fn with_session(mut self, session: TokioSession) -> Self {
        self.session = Some(session);
        self
    }

    /// An INDEPENDENT copy bound to a DEFERRED responder — what an escape hands
    /// back. The reply accumulator starts EMPTY rather than copied: replies the
    /// callback already asked for belong to the borrowed marshal's flush, and
    /// duplicating them here would send each one twice.
    fn deep_copy_deferred(&self, session: TokioSession) -> Self {
        Self {
            keyexpr: self.keyexpr.clone(),
            parameters: self.parameters.clone(),
            anyke: self.anyke,
            payload: self
                .payload
                .as_ref()
                .map(|s| BytesState::whole(s.payload.clone())),
            attachment: self
                .attachment
                .as_ref()
                .map(|s| BytesState::whole(s.payload.clone())),
            keyexpr_state: KeyexprState {
                keyexpr: self.keyexpr.clone(),
            },
            loaned_keyexpr: z_loaned_keyexpr_t::null_value(),
            loaned_payload: z_loaned_bytes_t::null_value(),
            loaned_attachment: z_loaned_bytes_t::null_value(),
            rid: self.rid,
            // The COPY is the escaped end of the chain: it carries the responder
            // rather than the raw session, so it can never be escaped again.
            session: None,
            escapes: Cell::new(0),
            deferred: Some(DeferredResponder {
                session,
                rid: self.rid,
            }),
            replies: UnsafeCell::new(Vec::new()),
        }
    }

    /// Take and clear the escape count.
    fn take_escapes(&self) -> u32 {
        self.escapes.replace(0)
    }

    /// Flush the accumulated replies into the dispatch's [`ReplyOut`].
    fn flush(&mut self, mut out: &mut dyn ReplyOut) {
        for reply in self.replies.get_mut().drain(..) {
            flush_one(&mut out, reply);
        }
    }

    /// Record one reply, routing it to the deferred seam when this marshal is
    /// an escaped one.
    fn push_reply(&self, reply: PendingReply) {
        match self.deferred.as_ref() {
            Some(responder) => responder.emit(&self.keyexpr, reply),
            // SAFETY: see the `replies` field docs — the accumulator is touched
            // only from the callback's own thread.
            None => unsafe { (*self.replies.get()).push(reply) },
        }
    }

    /// This marshal viewed as the borrowed query the C side gets.
    fn as_loaned(&self) -> *mut z_loaned_query_t {
        self as *const QueryMarshal as *mut z_loaned_query_t
    }
}

/// Read the marshal behind a loaned query.
///
/// # Safety
/// `query` must be null or a pointer this crate handed to a query callback (or
/// minted by [`z_query_loan`]) whose marshal is still alive.
unsafe fn query_marshal<'a>(query: *const z_loaned_query_t) -> Option<&'a QueryMarshal> {
    if query.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { &*(query as *const QueryMarshal) })
}

/// Build the wz-side queryable callback for ONE face from a shared C closure.
fn make_queryable_callback(
    closure: Arc<CQueryClosure>,
    session: TokioSession,
) -> impl FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static {
    move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
        let Some(call) = closure.call else {
            return;
        };
        let mut marshal = QueryMarshal::new(view).with_session(session.clone());
        // Bind AFTER the move out of `new` — final address only here.
        marshal.bind();
        let query_ptr = marshal.as_loaned();
        let ctx = closure.context.0;
        // SAFETY: `call` is the C callback and `marshal` outlives it. A panic
        // unwinding OUT of the C callback across this `extern "C"` boundary is
        // UB and would tear down the drive thread, so it is caught here.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            call(query_ptr, ctx);
        }));
        // One `ResponseFinal` hold per escape the callback made — see the module
        // doc for why this runs HERE and not inside the escape.
        for _ in 0..marshal.take_escapes() {
            session.hold_response_final(marshal.rid);
        }
        marshal.flush(out);
    }
}

/// Escape a borrowed query onto the heap, bound to a deferred responder — what
/// a query CHANNEL does when the callback hands it a query.
///
/// Returns a null handle when the marshal cannot be escaped: a marshal with no
/// session was built outside a dispatch and would produce an owned query with
/// no way to answer.
///
/// # Safety
/// `src` must be null or a pointer this crate handed to a query callback.
pub(crate) unsafe fn escape_query(src: *const z_loaned_query_t) -> Handle {
    // SAFETY: the caller's contract, delegated.
    let Some(marshal) = (unsafe { query_marshal(src) }) else {
        return std::ptr::null_mut();
    };
    let Some(session) = marshal.session.as_ref() else {
        return std::ptr::null_mut();
    };
    let mut boxed = Box::new(marshal.deep_copy_deferred(session.clone()));
    boxed.bind();
    marshal.escapes.set(marshal.escapes.get() + 1);
    Box::into_raw(boxed) as Handle
}

// --- the closure exports ----------------------------------------------------

/// Construct a query closure from its parts (zenoh-c `z_closure_query`).
///
/// Note upstream's argument ORDER — `(this_, call, drop, context)` — which is
/// not the struct's field order.
///
/// # Safety
/// `this_` must be valid and writable; `call` / `drop` must be null or valid C
/// function pointers.
#[no_mangle]
pub unsafe extern "C" fn z_closure_query(
    this_: *mut z_owned_closure_query_t,
    call: z_closure_query_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = z_owned_closure_query_t {
                context,
                call,
                drop,
            }
        };
    });
}

/// Drop a query closure that was never declared (zenoh-c
/// `z_closure_query_drop`).
///
/// # Safety
/// `closure_` must be null or a valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_query_drop(closure_: *mut z_moved_closure_query_t) {
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
        *owned = z_owned_closure_query_t::null_value();
        Z_OK
    });
}

// --- the queryable declaration ----------------------------------------------

/// zenoh-c `z_queryable_options_t` (`zenoh_commons.h:620-627`) — 8 bytes.
///
/// Mirrored FIELD FOR FIELD rather than sized: the struct is transparent
/// upstream and `z_queryable.c` writes `opts.complete = args.complete` into it,
/// so a wrong field order silently sets the wrong thing.
#[repr(C)]
pub struct z_queryable_options_t {
    /// Whether this queryable claims to hold the COMPLETE set of data for its
    /// keyexpr — what a querier's `AllComplete` target selects on.
    pub complete: bool,
    /// Which origins the queryable accepts queries from. Accepted and ignored;
    /// see the crate's residual list.
    pub allowed_origin: c_int,
}

const _: () = {
    assert!(std::mem::size_of::<z_queryable_options_t>() == 8);
    assert!(std::mem::align_of::<z_queryable_options_t>() == 4);
};

/// Fill default queryable options (zenoh-c `z_queryable_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_queryable_options_default(this_: *mut z_queryable_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract. `ZC_LOCALITY_DEFAULT` is 0 (`Any`).
    unsafe {
        *this_ = z_queryable_options_t {
            complete: false,
            allowed_origin: 0,
        }
    };
}

/// Behind a `z_owned_queryable_t` handle: the C queryable's id in the session's
/// SSOT. Dropping it retracts the declaration on every live face.
struct QueryableState {
    shared: Arc<SharedSession>,
    id: QblId,
}

impl Drop for QueryableState {
    fn drop(&mut self) {
        self.shared.undeclare_queryable(self.id);
    }
}

/// Declare a queryable (zenoh-c `z_declare_queryable`). Consumes the moved
/// closure on every path, for the reason [`crate::sub`] records.
///
/// # Safety
/// `session` must be a valid loaned session; `queryable` must be valid and
/// writable; `key_expr` must be a valid loaned keyexpr; `callback` must be a
/// valid moved closure; `options` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_declare_queryable(
    session: *const z_loaned_session_t,
    queryable: *mut z_owned_queryable_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_query_t,
    options: *mut z_queryable_options_t,
) -> ZResult {
    guarded(|| {
        if queryable.is_null() || callback.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, written before any fallible work.
        unsafe { *queryable = z_owned_queryable_t::null_value() };

        // Consume the moved closure FIRST, so every early return below frees the
        // caller's context exactly as upstream does.
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let cclosure = CQueryClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_query_t::null_value();

        // SAFETY: the caller's contract for both handles.
        let (Some(state), Some(ke)) = (unsafe { session_state(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();
        // The same outbound gate the subscriber path applies, hoisted so the
        // verdict is uniform whether or not a peer is connected yet.
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_EINVAL;
        }
        // A NULL options pointer is upstream's "defaults", not an error.
        let complete = if options.is_null() {
            false
        } else {
            // SAFETY: the caller's contract.
            unsafe { (*options).complete }
        };

        let id = state.shared.declare_queryable(ke, complete, {
            let closure = Arc::new(cclosure);
            Arc::new(move |face: &TokioSession| {
                Box::new(make_queryable_callback(closure.clone(), face.clone())) as Box<_>
            })
        });
        let handle = Box::into_raw(Box::new(QueryableState {
            shared: state.shared.clone(),
            id,
        })) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *queryable = z_owned_queryable_t::from_handle(handle) };
        Z_OK
    })
}

/// Undeclare a queryable (zenoh-c `z_undeclare_queryable`).
///
/// # Safety
/// `this_` must be null or a valid moved queryable.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_queryable(this_: *mut z_moved_queryable_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<QueryableState>` this crate leaked; its `Drop`
            // retracts the declaration.
            drop(unsafe { Box::from_raw(handle as *mut QueryableState) });
            unsafe { (*this_)._this = z_owned_queryable_t::null_value() };
        }
        Z_OK
    })
}

/// Drop a queryable (zenoh-c `z_queryable_drop`) — what `z_drop(z_move(qable))`
/// dispatches to.
///
/// # Safety
/// `this_` must be null or a valid moved queryable.
#[no_mangle]
pub unsafe extern "C" fn z_queryable_drop(this_: *mut z_moved_queryable_t) {
    // SAFETY: delegated — the slot is nulled there, so a double drop is a no-op.
    let _ = unsafe { z_undeclare_queryable(this_) };
}

/// Borrow a queryable (zenoh-c `z_queryable_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned queryable.
#[no_mangle]
pub unsafe extern "C" fn z_queryable_loan(
    this_: *const z_owned_queryable_t,
) -> *const z_loaned_queryable_t {
    this_ as *const z_loaned_queryable_t
}

/// `true` iff the owned queryable holds a live handle (zenoh-c
/// `z_internal_queryable_check`).
///
/// # Safety
/// `this_` must be null or a valid owned queryable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_queryable_check(this_: *const z_owned_queryable_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned queryable (zenoh-c `z_internal_queryable_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned queryable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_queryable_null(this_: *mut z_owned_queryable_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_queryable_t::null_value() };
    }
}

// --- the query accessors ----------------------------------------------------

/// Borrow a query's keyexpr (zenoh-c `z_query_keyexpr`).
///
/// # Safety
/// `this_` must be null or a live loaned query.
#[no_mangle]
pub unsafe extern "C" fn z_query_keyexpr(
    this_: *const z_loaned_query_t,
) -> *const z_loaned_keyexpr_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { query_marshal(this_) } {
            Some(m) => &m.loaned_keyexpr as *const z_loaned_keyexpr_t,
            None => std::ptr::null(),
        }
    })
}

/// Write a view over a query's selector parameters (zenoh-c
/// `z_query_parameters`).
///
/// # Safety
/// `this_` must be null or a live loaned query; `parameters` must be null or
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_query_parameters(
    this_: *const z_loaned_query_t,
    parameters: *mut z_view_string_t,
) {
    guard_val((), || {
        if parameters.is_null() {
            return;
        }
        // Written before the read so a caller that ignores a gravestone query
        // sees an empty string rather than a stale stack value.
        // SAFETY: the caller's contract.
        unsafe { *parameters = z_view_string_t::null_value() };
        // SAFETY: the caller's contract, delegated.
        if let Some(m) = unsafe { query_marshal(this_) } {
            // The parameters are raw bytes on the wire; upstream hands back a
            // string view over them and prints with `%.*s`, so a non-UTF-8
            // selector is passed through rather than rejected.
            let text = unsafe { std::str::from_utf8_unchecked(&m.parameters) };
            unsafe { *parameters = view_string_over(text) };
        }
    });
}

/// Borrow a query's VALUE payload, or NULL when it carried none (zenoh-c
/// `z_query_payload`).
///
/// NULL is the absence signal `z_queryable.c` branches on — see
/// [`QueryMarshal::payload`].
///
/// # Safety
/// `this_` must be null or a live loaned query.
#[no_mangle]
pub unsafe extern "C" fn z_query_payload(
    this_: *const z_loaned_query_t,
) -> *const z_loaned_bytes_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { query_marshal(this_) } {
            Some(m) if m.payload.is_some() => &m.loaned_payload as *const z_loaned_bytes_t,
            _ => std::ptr::null(),
        }
    })
}

/// Borrow a query's attachment, or NULL when it carried none (zenoh-c
/// `z_query_attachment`).
///
/// # Safety
/// `this_` must be null or a live loaned query.
#[no_mangle]
pub unsafe extern "C" fn z_query_attachment(
    this_: *const z_loaned_query_t,
) -> *const z_loaned_bytes_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { query_marshal(this_) } {
            Some(m) if m.attachment.is_some() => &m.loaned_attachment as *const z_loaned_bytes_t,
            _ => std::ptr::null(),
        }
    })
}

/// zenoh-c `z_query_reply_options_t` (`zenoh_commons.h:1023-1047`) — 40 bytes
/// on the no-unstable oracle, 48 with `Z_FEATURE_UNSTABLE_API`.
///
/// Mirrored field for field so rustc computes the size from the SAME list the
/// header declares, rather than from a transcribed constant — the discipline
/// R311y538 established for the publisher options structs, and the reason both
/// arms are written out below.
#[repr(C)]
pub struct z_query_reply_options_t {
    /// Reply value encoding. Accepted and ignored; see the residual list.
    pub encoding: *mut c_void,
    /// Congestion control. Accepted and ignored.
    pub congestion_control: c_int,
    /// Priority. Accepted and ignored.
    pub priority: c_int,
    /// Express flag. Accepted and ignored.
    pub is_express: bool,
    /// Explicit timestamp. Accepted and ignored.
    pub timestamp: *mut c_void,
    /// Source info — present only under `Z_FEATURE_UNSTABLE_API`.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub source_info: *mut c_void,
    /// Reply attachment. CARRIED, unlike the fields above: it rides the reply's
    /// own body and a queryable that attaches metadata is answering a different
    /// question than one that does not.
    pub attachment: *mut z_moved_bytes_t,
}

/// Fill default reply options (zenoh-c `z_query_reply_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_options_default(this_: *mut z_query_reply_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract. Every default is zero / null except the
    // enums, whose defaults are also 0 in upstream's tables.
    unsafe {
        *this_ = z_query_reply_options_t {
            encoding: std::ptr::null_mut(),
            congestion_control: 0,
            priority: 5,
            is_express: false,
            timestamp: std::ptr::null_mut(),
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: std::ptr::null_mut(),
            attachment: std::ptr::null_mut(),
        }
    };
}

/// Reply to a query (zenoh-c `z_query_reply`), consuming the payload.
///
/// The `reply ⊆ query` contract is enforced here rather than trusted: a reply
/// whose keyexpr the query does not cover is rejected with `Z_EINVAL` instead of
/// being put on the wire for a peer to drop. Routed through the same
/// intersection SSOT the RECEIVE side uses.
///
/// # Safety
/// `this_` must be null or a live loaned query; `key_expr` must be null or a
/// valid loaned keyexpr; `payload` must be null or a valid moved bytes, which is
/// consumed; `options` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply(
    this_: *const z_loaned_query_t,
    key_expr: *const z_loaned_keyexpr_t,
    payload: *mut z_moved_bytes_t,
    options: *mut z_query_reply_options_t,
) -> ZResult {
    guarded(|| {
        // Consume the payload FIRST and on every path — upstream's ownership
        // transfer is unconditional, so an early return that skipped it would
        // leak the caller's payload.
        // SAFETY: the caller's contract.
        let taken = unsafe { crate::bytes::take_payload(payload) };
        let attachment = if options.is_null() {
            None
        } else {
            // SAFETY: the caller's contract.
            unsafe { crate::bytes::take_payload((*options).attachment) }
        };

        // SAFETY: the caller's contract, delegated.
        let Some(marshal) = (unsafe { query_marshal(this_) }) else {
            return Z_ENULL;
        };
        // SAFETY: the caller's contract.
        let Some(ke) = (unsafe { keyexpr_str(key_expr) }) else {
            return Z_ENULL;
        };
        let Some(payload) = taken else {
            return Z_ENULL;
        };
        if !reply_keyexpr_is_covered(&marshal.keyexpr, ke, marshal.anyke) {
            return Z_EINVAL;
        }
        marshal.push_reply(PendingReply::Put {
            keyexpr: ke.to_owned(),
            payload,
            attachment,
        });
        Z_OK
    })
}

// --- the OWNED query --------------------------------------------------------

/// Borrow an owned query (zenoh-c `z_query_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned query.
#[no_mangle]
pub unsafe extern "C" fn z_query_loan(this_: *const z_owned_query_t) -> *const z_loaned_query_t {
    guard_val(std::ptr::null(), || {
        if this_.is_null() {
            return std::ptr::null();
        }
        // The handle IS the marshal pointer, which is what the accessors read —
        // so a loan is a read of slot 0, not a cast of the owned struct.
        // SAFETY: the caller's contract.
        unsafe { (*this_).handle as *const z_loaned_query_t }
    })
}

/// `true` iff the owned query holds a live marshal (zenoh-c
/// `z_internal_query_check`).
///
/// # Safety
/// `this_` must be null or a valid owned query.
#[no_mangle]
pub unsafe extern "C" fn z_internal_query_check(this_: *const z_owned_query_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned query (zenoh-c `z_internal_query_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned query.
#[no_mangle]
pub unsafe extern "C" fn z_internal_query_null(this_: *mut z_owned_query_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_query_t::null_value() };
    }
}

/// Drop an owned query (zenoh-c `z_query_drop`) — which is what SENDS the
/// `ResponseFinal` for an escaped query, via [`DeferredResponder::drop`].
///
/// # Safety
/// `this_` must be null or a valid moved query.
#[no_mangle]
pub unsafe extern "C" fn z_query_drop(this_: *mut z_moved_query_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<QueryMarshal>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut QueryMarshal) });
            unsafe { (*this_)._this = z_owned_query_t::null_value() };
        }
        Z_OK
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `reply ⊆ query` gate is an INTERSECTION, so a wildcard query admits
    /// a concrete reply — the ordinary case, which string equality would
    /// reject.
    #[test]
    fn the_reply_gate_intersects_rather_than_compares() {
        assert!(reply_keyexpr_is_covered("demo/**", "demo/a/b", false));
        assert!(reply_keyexpr_is_covered("demo/*", "demo/a", false));
        assert!(!reply_keyexpr_is_covered("demo/a", "other/a", false));
        // `_anyke` waives the gate entirely, which is what it is for.
        assert!(reply_keyexpr_is_covered("demo/a", "other/a", true));
    }

    /// `_anyke` is recognised both bare and with a value, and NOT as a prefix
    /// of some other field — `_anykey=1` is a different selector.
    #[test]
    fn anyke_is_read_off_the_selector_exactly() {
        assert!(parameters_has_anyke(b"_anyke"));
        assert!(parameters_has_anyke(b"a=1&_anyke&b=2"));
        assert!(parameters_has_anyke(b"_anyke=true"));
        assert!(!parameters_has_anyke(b"_anykey=1"));
        assert!(!parameters_has_anyke(b""));
    }

    /// Options defaults are what upstream's are, and `complete` starts FALSE —
    /// `z_queryable.c` sets it from its own flag immediately after, so a
    /// default of `true` would make an unflagged queryable claim completeness.
    #[test]
    fn the_queryable_options_default_is_incomplete_and_any_origin() {
        let mut opts = z_queryable_options_t {
            complete: true,
            allowed_origin: 99,
        };
        // SAFETY: `opts` is a live local.
        unsafe { z_queryable_options_default(&mut opts) };
        assert!(!opts.complete);
        assert_eq!(opts.allowed_origin, 0);
    }

    /// Every accessor answers a NULL query without dereferencing it.
    #[test]
    fn the_query_accessors_answer_null_without_dereferencing_it() {
        // SAFETY: passing NULL is exactly what these guards exist for.
        unsafe {
            assert!(z_query_keyexpr(std::ptr::null()).is_null());
            assert!(z_query_payload(std::ptr::null()).is_null());
            assert!(z_query_attachment(std::ptr::null()).is_null());
            assert!(z_query_loan(std::ptr::null()).is_null());
            assert!(!z_internal_query_check(std::ptr::null()));
            let mut params = z_view_string_t::null_value();
            z_query_parameters(std::ptr::null(), &mut params);
            assert_eq!(params.len, 0);
            assert_eq!(
                z_query_reply(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut()
                ),
                Z_ENULL
            );
            z_query_drop(std::ptr::null_mut());
        }
    }
}

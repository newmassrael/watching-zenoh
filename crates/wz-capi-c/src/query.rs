// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use wz_runtime_tokio::query_sink::{QueryView, ReplyMeta, ReplyOut};
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
//
// R311y554 — and now, as on the subscriber plane, that premise no longer rests
// on a locality pin. `z_declare_queryable` honours the caller's
// `allowed_origin`, so an in-process `z_get` CAN reach this session's own
// queryable; what keeps the handler off the C thread is that the session runs
// `LocalDeliveryDrain::DriveTask` and the local query's handler fires from the
// staged queue that `SharedSession::dispatch` drains.
unsafe impl Sync for CQueryClosure {}

/// One reply the C callback asked for, held until it can be flushed.
enum PendingReply {
    /// `z_query_reply` — a Put-form reply under an explicit keyexpr.
    Put {
        keyexpr: String,
        payload: Vec<u8>,
        /// R311y547 — the reply's value encoding, from
        /// `z_query_reply_options_t::encoding`. The `ReplyOut` seam has
        /// carried this slot since the storage per-version reply landed
        /// (`reply_keyed_encoded` / `reply_keyed_attached` both take it); this
        /// crate was passing `None` into it, which is why a queryable that set
        /// an encoding was answering with `zenoh/bytes` on the wire.
        encoding: Option<wz_runtime_tokio::sample::EncodingHint>,
        attachment: Option<Vec<u8>>,
        /// R311y563 — the reply's timestamp (the inner body T-flag).
        timestamp: Option<wz_runtime_tokio::sample::TimestampHint>,
        /// R311y563 — the reply's `(zid, eid, sn)` (the body ext 0x01). Owned,
        /// because a reply is flushed after the callback returns and the
        /// caller's `z_moved_source_info_t` is consumed at CALL time.
        source_info: Option<wz_runtime_tokio::sample::SourceInfo>,
    },
    /// `z_query_reply_del` — a Del-form reply, R311y565.
    ///
    /// No `encoding` field, and that is WIRE-FAITHFUL rather than an omission:
    /// the codec reads an encoding only in the Put branch
    /// (`vendor/zenoh-pico/src/protocol/codec/message.c:269-276`), so a Del that
    /// carried one would put a field no decoder reads on the wire. Upstream's
    /// `z_query_reply_del_options_t` agrees — it declares no encoding either.
    Del {
        keyexpr: String,
        attachment: Option<Vec<u8>>,
        timestamp: Option<wz_runtime_tokio::sample::TimestampHint>,
        source_info: Option<wz_runtime_tokio::sample::SourceInfo>,
    },
    /// `z_query_reply_err` — an ERROR-form reply, R311y568.
    ///
    /// No keyexpr, and that is upstream's own signature rather than an omission:
    /// `z_query_reply_err` takes no `key_expr` argument, because a zenoh reply
    /// ERROR is a property of the QUERY (`ResponseBody::Err`) and not of a key.
    /// The keyexpr-coverage gate the Put and Del arms run therefore has nothing
    /// to check here.
    ///
    /// The encoding IS carried, unlike on the Del arm: the Err body is a
    /// `zenoh_protocol::zenoh::Err` whose value has its own encoding field, and
    /// `z_query_reply_err_options_t` declares exactly that one field.
    Err {
        payload: Vec<u8>,
        encoding: Option<wz_runtime_tokio::sample::EncodingHint>,
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
    /// R311y834 — the escaped query's own `_anyke`, for the reason its
    /// `wz-capi-pico` twin carries one: the deferred emit must build the SAME
    /// acceptance policy as the in-dispatch leg, and neither default is right
    /// without the query's actual selector.
    accept: wz_runtime_tokio::reply_acceptance::ReplyKeyExpr,
}

impl DeferredResponder {
    /// Emit one reply NOW, through the same [`QueryResponder`] path the
    /// in-dispatch flush uses, so the deferred and immediate legs cannot drift.
    fn emit(&self, query_keyexpr: &str, reply: PendingReply) {
        let mut replies: Vec<QueryReply> = Vec::new();
        {
            let mut responder = QueryResponder::new(
                self.rid,
                query_keyexpr.to_owned(),
                self.accept,
                &mut replies,
            );
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

/// R311y563 — TAKE `z_query_reply_options_t::source_info`, on the arm that has
/// one. A helper for the same reason the querier's is: the call sits inside a
/// TUPLE expression, where an attribute cannot go.
///
/// # Safety
/// `options` must be null or a valid reply-options struct.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
unsafe fn reply_source_info(
    options: *mut z_query_reply_options_t,
) -> Option<wz_runtime_tokio::sample::SourceInfo> {
    // SAFETY: the caller's contract.
    unsafe { crate::source_info::borrowed_source_info((*options).source_info) }
}

/// The no-unstable arm: upstream does not declare the field there.
///
/// # Safety
/// `options` is unused; the signature matches the sibling above.
#[cfg(feature = "zenoh-c-no-unstable-api")]
unsafe fn reply_source_info(
    _options: *mut z_query_reply_options_t,
) -> Option<wz_runtime_tokio::sample::SourceInfo> {
    None
}

/// Route ONE accumulated reply into a [`ReplyOut`]. Shared by the in-dispatch
/// flush and the deferred emit so the two cannot answer differently.
fn flush_one(out: &mut &mut dyn ReplyOut, reply: PendingReply) {
    match reply {
        // R311y563 — ONE seam carries all four arms now
        // ([`wz_runtime_tokio::query_sink::ReplyMeta`], added the same round for
        // the pico ABI's identical problem). The previous shape had to CHOOSE
        // between `reply_keyed_attached` (attachment, no timestamp) and
        // `reply_keyed_encoded` (neither), because no arm carried an attachment
        // alongside a timestamp and source_info — which is exactly the
        // combination `z_query_reply_options_t` lets a caller set.
        PendingReply::Put {
            keyexpr,
            payload,
            encoding,
            attachment,
            timestamp,
            source_info,
        } => out.reply_keyed_meta(
            &keyexpr,
            &payload,
            ReplyMeta::new()
                .with_encoding(encoding.as_ref())
                .with_timestamp(timestamp.as_ref())
                .with_source_info(source_info.as_ref())
                .with_attachment(attachment.as_deref()),
        ),
        // The SAME `ReplyMeta` seam, minus the payload and the encoding — so a
        // Del reply and a Put reply cannot drift on how a timestamp or a
        // source_info reaches the wire.
        PendingReply::Del {
            keyexpr,
            attachment,
            timestamp,
            source_info,
        } => out.reply_keyed_del_meta(
            &keyexpr,
            ReplyMeta::new()
                .with_timestamp(timestamp.as_ref())
                .with_source_info(source_info.as_ref())
                .with_attachment(attachment.as_deref()),
        ),
        // R311y568 — the ERROR arm. A separate seam method rather than a
        // `ReplyMeta` variant because the wire body differs in KIND, not in
        // metadata: `reply_err` emits `ResponseBody::Err`, which carries neither
        // a keyexpr nor a timestamp nor an attachment. The `(id, schema)` split
        // is what [`ReplyOut::reply_err`] takes, so the hint is projected here
        // rather than at the call site.
        PendingReply::Err { payload, encoding } => {
            let (id, schema) = match encoding.as_ref() {
                // UNPACKED. `EncodingHint::packed_id` is the wire word
                // `(id << 1) | has_schema` (`hint_from_parts`), while
                // `ReplyOut::reply_err` documents its `encoding_id` as the
                // content-type PREFIX and re-packs it itself
                // (`response_build.rs::encoding`). Passing the packed word would
                // double-shift and put a different content type on the wire.
                Some(hint) => (Some(hint.packed_id >> 1), hint.schema.as_deref()),
                None => (None, None),
            };
            out.reply_err(id, schema, &payload);
        }
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
    /// R311y568 — the query VALUE's encoding, ALWAYS present.
    ///
    /// Not an `Option`, for the reason [`crate::sample::SampleMarshal::encoding`]
    /// gives: upstream's `z_query_encoding` returns a non-optional
    /// `const z_loaned_encoding_t *` off a Rust `Encoding` value, so a query
    /// that carried no encoding ext reports the DEFAULT rather than NULL.
    ///
    /// Note the contrast with [`Self::payload`] one field up, which IS an
    /// `Option` because `z_queryable.c` branches on its NULL. The two shapes
    /// differ because upstream's two signatures do.
    encoding: crate::encoding::EncodingState,
    /// R2261 (open-debt item 593) — the QUERIER's `(zid, eid, sn)`, or `None`
    /// when the query carried no source-info ext.
    ///
    /// ⛔ Item 593 recorded this as the one stray that "genuinely needs a value
    /// `QueryMarshal` does not carry", and the first half is true while the
    /// second is narrower than it reads: the value is carried, one layer up.
    /// `QueryView::source_info` has existed since the accessor was added,
    /// `BorrowedQuery` has the field, and the receive path already fills it
    /// (`session/queryable.rs` — `source_info: owned.source_info.as_ref()`).
    /// What was missing was this marshal keeping it, so a C entry point could
    /// read it back — the SAME shape R2258 measured for the other two strays,
    /// one layer deeper.
    ///
    /// Stored as the wz type and VIEWED through `source_info_c`, the contract
    /// [`crate::sample::SampleMarshal`] states for its twin: the accessor hands
    /// out a pointer whose lifetime is this marshal's.
    source_info: Option<wz_runtime_tokio::sample::SourceInfo>,
    /// The C view [`z_query_source_info`] returns a pointer to. A VALUE since
    /// zenoh-c 1.10.0 retired the owned/loaned split.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    source_info_c: crate::source_info::z_source_info_t,
    keyexpr_state: KeyexprState,
    loaned_keyexpr: z_loaned_keyexpr_t,
    loaned_payload: z_loaned_bytes_t,
    loaned_attachment: z_loaned_bytes_t,
    /// The loaned view `z_query_encoding` returns, aimed at this marshal's own
    /// [`Self::encoding`].
    loaned_encoding: crate::abi::z_loaned_encoding_t,
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
            encoding: match view.encoding() {
                Some(hint) => crate::encoding::EncodingState::from_hint(hint),
                None => crate::encoding::EncodingState::default_encoding(),
            },
            source_info: view.source_info().cloned(),
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info_c: crate::source_info::z_source_info_t::empty(),
            keyexpr_state: KeyexprState::new(keyexpr.clone()),
            keyexpr,
            loaned_keyexpr: z_loaned_keyexpr_t::null_value(),
            loaned_payload: z_loaned_bytes_t::null_value(),
            loaned_attachment: z_loaned_bytes_t::null_value(),
            loaned_encoding: crate::abi::z_loaned_encoding_t::null_value(),
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
        self.loaned_encoding = crate::abi::z_loaned_encoding_t::from_handle(
            &self.encoding as *const crate::encoding::EncodingState as *mut c_void,
        );
        // R2261 — the same conversion `SampleMarshal::bind` does, at the same
        // moment and for the same reason: the C view is a VALUE living inside
        // this marshal, so it can only be filled once the marshal is at its
        // final address.
        #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
        {
            self.source_info_c = match self.source_info.as_ref() {
                Some(info) => crate::source_info::z_source_info_t::from_runtime(info),
                None => crate::source_info::z_source_info_t::empty(),
            };
        }
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
            encoding: self.encoding.deep_copy(),
            // R2261 — the ESCAPED copy keeps the querier's identity. A query
            // escaped into a `z_owned_query_t` outlives the callback, and the
            // whole reason a C program escapes one is to answer it later; a
            // copy that dropped the source info would answer `NULL` from a
            // query whose borrowed twin answered a zid.
            source_info: self.source_info.clone(),
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info_c: crate::source_info::z_source_info_t::empty(),
            keyexpr_state: KeyexprState::new(self.keyexpr.clone()),
            loaned_keyexpr: z_loaned_keyexpr_t::null_value(),
            loaned_payload: z_loaned_bytes_t::null_value(),
            loaned_attachment: z_loaned_bytes_t::null_value(),
            loaned_encoding: crate::abi::z_loaned_encoding_t::null_value(),
            rid: self.rid,
            // The COPY is the escaped end of the chain: it carries the responder
            // rather than the raw session, so it can never be escaped again.
            session: None,
            escapes: Cell::new(0),
            deferred: Some(DeferredResponder {
                session,
                rid: self.rid,
                accept: if self.anyke {
                    wz_runtime_tokio::reply_acceptance::ReplyKeyExpr::Any
                } else {
                    wz_runtime_tokio::reply_acceptance::ReplyKeyExpr::MatchingQuery
                },
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
    /// Which origins the queryable accepts queries from. R311y554 — READ; it
    /// becomes the wz queryable's `allowed_origin` predicate.
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

/// Both fields of a `z_queryable_options_t`, resolved, with upstream's defaults
/// standing in for a NULL pointer.
///
/// R311y554 — extracted so `allowed_origin` is read at the SAME seam as
/// `complete`. They come from one struct and reading one while ignoring the
/// other is precisely how the second stayed "carried for layout" for six
/// rounds; a function that returns both cannot forget one.
///
/// # Safety
/// `options` must be null or a valid queryable-options struct.
pub(crate) unsafe fn queryable_declare_params(
    options: *const z_queryable_options_t,
) -> (bool, wz_runtime_tokio::locality::Locality) {
    if options.is_null() {
        // `z_queryable_options_default` writes `complete = false` and
        // `allowed_origin = ZC_LOCALITY_ANY`.
        return (false, wz_runtime_tokio::locality::Locality::Any);
    }
    // SAFETY: the caller's contract.
    let o = unsafe { &*options };
    (o.complete, crate::put::locality_from_c(o.allowed_origin))
}

/// Behind a `z_owned_queryable_t` handle: the C queryable's id in the session's
/// SSOT. Dropping it retracts the declaration on every live face.
struct QueryableState {
    shared: Arc<SharedSession>,
    id: QblId,
    /// R311y568 — the keyexpr this queryable was declared under, so
    /// [`z_queryable_keyexpr`] can answer.
    keyexpr: crate::keyexpr::DeclaredKeyexpr,
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
        // SAFETY: the caller's contract for the options struct.
        let (complete, allowed_origin) = unsafe { queryable_declare_params(options) };

        let declared = ke.clone();
        let id = state
            .shared
            .declare_queryable(ke, complete, allowed_origin, {
                let closure = Arc::new(cclosure);
                Arc::new(move |face: &TokioSession| {
                    Box::new(make_queryable_callback(closure.clone(), face.clone())) as Box<_>
                })
            });
        let mut boxed = Box::new(QueryableState {
            shared: state.shared.clone(),
            id,
            keyexpr: crate::keyexpr::DeclaredKeyexpr::new(declared),
        });
        // Bind AFTER boxing — the state is at its final address only here.
        boxed.keyexpr.bind();
        let handle = Box::into_raw(boxed) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *queryable = z_owned_queryable_t::from_handle(handle) };
        Z_OK
    })
}

/// Declare a queryable the C side never holds (zenoh-c
/// `z_declare_background_queryable`): it lives until the session is closed.
///
/// R311y568. The subscriber twin has existed since the declare plane landed;
/// this one is the same construction for the same reason, and its absence was a
/// link error for any program using upstream's background form on the query
/// side.
///
/// Implemented by declaring into a LOCAL owned handle and DISCARDING it, exactly
/// as [`crate::sub::z_declare_background_subscriber`] does — see that function
/// for the full argument, including why the discard is a deliberate leak and why
/// `mem::forget` here would be a no-op that merely looked load-bearing.
///
/// # Safety
/// `session` must be a valid loaned session; `key_expr` must be a valid loaned
/// keyexpr; `callback` must be a valid moved closure; `options` must be null or
/// valid.
#[no_mangle]
pub unsafe extern "C" fn z_declare_background_queryable(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_query_t,
    options: *mut z_queryable_options_t,
) -> ZResult {
    let mut sink = z_owned_queryable_t::null_value();
    // SAFETY: the caller's contract, delegated — the local sink absorbs the
    // handle the owned form would have written out, and then goes out of scope
    // without reclaiming it.
    unsafe { z_declare_queryable(session, &mut sink, key_expr, callback, options) }
}

/// This queryable's GLOBAL ENTITY ID (zenoh-c `z_queryable_id`).
///
/// R311y568. UNSTABLE-gated, as upstream gates it and as its return type
/// requires — see [`crate::sub::z_subscriber_id`] for the full argument.
///
/// # Safety
/// `queryable` must be null or a valid loaned queryable.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_queryable_id(
    queryable: *const z_loaned_queryable_t,
) -> crate::advanced::z_entity_global_id_t {
    guard_val(crate::advanced::z_entity_global_id_t::empty(), || {
        if queryable.is_null() {
            return crate::advanced::z_entity_global_id_t::empty();
        }
        // SAFETY: the caller's contract — a live `Box<QueryableState>`.
        let handle = unsafe { (*queryable).handle };
        if handle.is_null() {
            return crate::advanced::z_entity_global_id_t::empty();
        }
        // SAFETY: as above.
        let state = unsafe { &*(handle as *const QueryableState) };
        crate::advanced::z_entity_global_id_t::for_entity(&state.shared, queryable as *const c_void)
    })
}

/// The keyexpr a queryable was declared under (zenoh-c `z_queryable_keyexpr`).
///
/// R311y568. The borrow is valid for as long as the queryable is, which is
/// upstream's contract: the state is boxed and the view is aimed at its own
/// field, so the pointer outlives every call but not the declaration.
///
/// # Safety
/// `queryable` must be null or a valid loaned queryable.
#[no_mangle]
pub unsafe extern "C" fn z_queryable_keyexpr(
    queryable: *const z_loaned_queryable_t,
) -> *const z_loaned_keyexpr_t {
    guard_val(std::ptr::null(), || {
        if queryable.is_null() {
            return std::ptr::null();
        }
        // SAFETY: the caller's contract — the handle is a live
        // `Box<QueryableState>` this crate leaked.
        let handle = unsafe { (*queryable).handle };
        if handle.is_null() {
            return std::ptr::null();
        }
        // SAFETY: as above.
        unsafe { &*(handle as *const QueryableState) }
            .keyexpr
            .as_loaned()
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

/// zenoh-c `z_reply_keyexpr_t` (`zenoh_commons.h:171-181`).
///
/// Two values and a `DEFAULT` alias for the second, so the C spelling
/// `Z_REPLY_KEYEXPR_DEFAULT` and `Z_REPLY_KEYEXPR_MATCHING_QUERY` are the same
/// discriminant — which is why this is a plain `u32` constant pair rather than
/// a Rust enum with three variants.
pub const Z_REPLY_KEYEXPR_ANY: u32 = 0;
/// See [`Z_REPLY_KEYEXPR_ANY`]. `Z_REPLY_KEYEXPR_DEFAULT` aliases this one.
pub const Z_REPLY_KEYEXPR_MATCHING_QUERY: u32 = 1;

/// Whether this query accepts replies under ANY key (zenoh-c
/// `z_query_accepts_replies`).
///
/// R2258 (open-debt item 593) — the second of the twelve strays, and like
/// `z_session_id` it needed no new machinery: the answer is the `_anyke`
/// selector token, which `QueryMarshal` has carried in its `anyke` field
/// since the marshal was written and which `parameters_has_anyke` derives.
///
/// ⚠ The item recorded these strays as "accessors, each needing a value wz's
/// marshals do not carry yet". MEASURED, that is the opposite of the case here
/// — the marshal carries it and the reply path already CONSULTS it, so the only
/// thing missing was the C entry point that reads it back.
///
/// A gravestoned query answers `MATCHING_QUERY`, which is upstream's
/// `Z_REPLY_KEYEXPR_DEFAULT`: the conservative half, since a caller that
/// mistakes a dead query for one accepting anything would send a reply the
/// responder is supposed to refuse.
///
/// # Safety
/// `this_` must be null or a live loaned query.
#[no_mangle]
pub unsafe extern "C" fn z_query_accepts_replies(this_: *const z_loaned_query_t) -> u32 {
    guard_val(Z_REPLY_KEYEXPR_MATCHING_QUERY, || {
        // SAFETY: the caller's contract.
        match unsafe { query_marshal(this_) } {
            Some(m) if m.anyke => Z_REPLY_KEYEXPR_ANY,
            _ => Z_REPLY_KEYEXPR_MATCHING_QUERY,
        }
    })
}

/// The QUERIER's `(zid, eid, sn)`, or NULL when the query carried none
/// (zenoh-c `z_query_source_info`).
///
/// R2261 (open-debt item 593) — the LAST of the twelve strays, and the one the
/// item said would need a value wz did not carry. Re-measured, the value was
/// carried: `QueryView::source_info` is filled by the receive path out of the
/// query's own source-info ext, and what this round added is the marshal
/// keeping it plus this door. The item's sentence was right about
/// `QueryMarshal` and wrong about the tree.
///
/// NULL rather than a zeroed struct for the absent case, because upstream
/// returns `Option<&z_source_info_t>` (`~/zenoh-c-ref/src/queryable.rs` @
/// `pub extern "C" fn z_query_source_info`) and a C program written against it
/// checks the pointer. A zeroed struct would read as a real querier whose zid
/// is sixteen zero bytes.
///
/// The pointer borrows the marshal, exactly as [`z_sample_source_info`] does —
/// see that function for the lifetime contract.
///
/// UNSTABLE-gated as upstream gates it: MEASURED with `nm -D` against all four
/// provisioned 1.10.0 oracles, the two no-unstable arms define it ZERO times.
///
/// # Safety
/// `this_` must be null or a live loaned query.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_query_source_info(
    this_: *const z_loaned_query_t,
) -> *const crate::source_info::z_source_info_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { query_marshal(this_) } {
            Some(m) if m.source_info.is_some() => {
                &m.source_info_c as *const crate::source_info::z_source_info_t
            }
            _ => std::ptr::null(),
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

// --- R311y568: the query's mutable accessors + its encoding + the owned pair -
//
// Six symbols upstream defines and this cdylib did not. The three `_mut`
// spellings are what a C program calling `z_bytes_writer_*` on a query's payload
// needs, and `z_query_encoding` is the read that was blocked until the marshal
// carried one.

/// The query VALUE's encoding (zenoh-c `z_query_encoding`).
///
/// NEVER null for a live query — see [`QueryMarshal::encoding`] for why an absent
/// ext reports the default rather than NULL.
///
/// # Safety
/// `this_` must be null or a live loaned query.
#[no_mangle]
pub unsafe extern "C" fn z_query_encoding(
    this_: *const z_loaned_query_t,
) -> *const crate::abi::z_loaned_encoding_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { query_marshal(this_) } {
            Some(m) => &m.loaned_encoding as *const crate::abi::z_loaned_encoding_t,
            None => std::ptr::null(),
        }
    })
}

/// Mutably borrow a query's VALUE payload (zenoh-c `z_query_payload_mut`).
///
/// Keeps [`z_query_payload`]'s NULL-on-absent gate: upstream's own
/// `z_queryable.c` branches on the null, and the mutable spelling reaching for a
/// present-but-empty blob instead would take the other branch.
///
/// # Safety
/// `this_` must be null or a live loaned query.
#[no_mangle]
pub unsafe extern "C" fn z_query_payload_mut(
    this_: *mut z_loaned_query_t,
) -> *mut z_loaned_bytes_t {
    guard_val(std::ptr::null_mut(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { query_marshal(this_) } {
            Some(m) if m.payload.is_some() => {
                &m.loaned_payload as *const z_loaned_bytes_t as *mut z_loaned_bytes_t
            }
            _ => std::ptr::null_mut(),
        }
    })
}

/// Mutably borrow a query's ATTACHMENT (zenoh-c `z_query_attachment_mut`).
///
/// # Safety
/// `this_` must be null or a live loaned query.
#[no_mangle]
pub unsafe extern "C" fn z_query_attachment_mut(
    this_: *mut z_loaned_query_t,
) -> *mut z_loaned_bytes_t {
    guard_val(std::ptr::null_mut(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { query_marshal(this_) } {
            Some(m) if m.attachment.is_some() => {
                &m.loaned_attachment as *const z_loaned_bytes_t as *mut z_loaned_bytes_t
            }
            _ => std::ptr::null_mut(),
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
    /// Reply value encoding. R311y547 — READ, and carried on the reply's own
    /// `MsgPut` body (the E-flag), which is where a foreign querier reads it
    /// from. Typed rather than `*mut c_void` now that the field is used; the
    /// layout is unchanged, a pointer being a pointer.
    pub encoding: *mut crate::abi::z_moved_encoding_t,
    /// Congestion control. Accepted and ignored.
    pub congestion_control: c_int,
    /// Priority. Accepted and ignored.
    pub priority: c_int,
    /// Express flag. Accepted and ignored.
    pub is_express: bool,
    /// Explicit timestamp. R311y563 — READ. It was "accepted and ignored" on
    /// the reasoning that the type did not exist here; `z_timestamp_t` landed
    /// at R311y557 and the reason expired with it. BORROWED, not moved:
    /// upstream declares `struct z_timestamp_t *timestamp`, a concrete struct
    /// the caller keeps.
    pub timestamp: *mut crate::timestamp::z_timestamp_t,
    /// Source info — present only under `Z_FEATURE_UNSTABLE_API`. R311y563:
    /// READ and CONSUMED, stamped onto the reply body's source_info ext.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub source_info: *const crate::source_info::z_source_info_t,
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
        let (encoding, attachment, timestamp, source_info) = if options.is_null() {
            (None, None, None, None)
        } else {
            // SAFETY: the caller's contract. The encoding and the attachment
            // are both TAKEN, as upstream specifies for owned options fields —
            // an encoding may be heap-owned since R311y564. Both happen before
            // any early return, so a failed reply still consumes what upstream
            // would have consumed.
            unsafe {
                (
                    crate::encoding::take_moved_encoding((*options).encoding),
                    crate::bytes::take_payload((*options).attachment),
                    // BORROWED — a concrete struct the caller keeps.
                    crate::timestamp::timestamp_hint(
                        (*options).timestamp as *const std::ffi::c_void,
                    ),
                    // TAKEN — a `z_moved_*` field, consumed on every path.
                    reply_source_info(options),
                )
            }
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
            encoding,
            attachment,
            timestamp,
            source_info,
        });
        Z_OK
    })
}

/// Options for `z_query_reply_del` (`zenoh_commons.h:1052-1081`).
///
/// R311y565 — the struct was NOT DECLARED AT ALL until this round, which is a
/// bigger gap than an unread field: `z_query_reply_del` had no signature to take
/// and a C program that wanted to answer a query with a DELETE could not be
/// written against this ABI. Carried as named debt since R311y563.
///
/// Upstream's fields in upstream's order, minus the encoding its Put sibling
/// has — see [`PendingReply::Del`] for why a Del carries none.
#[repr(C)]
pub struct z_query_reply_del_options_t {
    /// Congestion control. Accepted and ignored, as on the Put reply.
    pub congestion_control: c_int,
    /// Priority. Accepted and ignored.
    pub priority: c_int,
    /// Express flag. Accepted and ignored.
    pub is_express: bool,
    /// Explicit timestamp. BORROWED — a concrete struct the caller keeps.
    pub timestamp: *mut crate::timestamp::z_timestamp_t,
    /// Source info — present only under `Z_FEATURE_UNSTABLE_API`. TAKEN.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub source_info: *const crate::source_info::z_source_info_t,
    /// Reply attachment. TAKEN and carried.
    pub attachment: *mut z_moved_bytes_t,
}

/// Fill default del-reply options (zenoh-c `z_query_reply_del_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_del_options_default(
    this_: *mut z_query_reply_del_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract. The scalar defaults are the Put reply's,
    // read from the same place: `z_query_reply_options_default` above.
    unsafe {
        *this_ = z_query_reply_del_options_t {
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

/// zenoh-c `z_query_reply_err_options_t` (`zenoh_commons.h:1086-1091`) — 8
/// bytes, one field.
///
/// R311y568 — NOT DECLARED AT ALL until this round, the same gap
/// [`z_query_reply_del_options_t`] had at y565: `z_query_reply_err` had no
/// signature to take, so a C program that wanted to answer a query with an
/// application-level ERROR could not be written against this ABI.
#[repr(C)]
pub struct z_query_reply_err_options_t {
    /// The encoding of the ERROR payload. TAKEN — a `z_moved_*` field, consumed
    /// on every path including the error ones.
    pub encoding: *mut crate::abi::z_moved_encoding_t,
}

/// Fill default err-reply options (zenoh-c `z_query_reply_err_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_err_options_default(
    this_: *mut z_query_reply_err_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_query_reply_err_options_t {
            encoding: std::ptr::null_mut(),
        }
    };
}

/// Answer a query with an application-level ERROR (zenoh-c
/// `z_query_reply_err`).
///
/// The third reply form, alongside [`z_query_reply`] and [`z_query_reply_del`],
/// and the only one that takes NO keyexpr — see [`PendingReply::Err`] for why
/// that is upstream's signature rather than an omission here, and why the
/// coverage gate the other two run has nothing to check.
///
/// Accumulated into the query marshal like its siblings, so an error reply
/// emitted from an ESCAPED query reaches the wire through the same
/// [`DeferredResponder`] path.
///
/// # Safety
/// `this_` must be null or a live loaned query; `payload` must be null or a valid
/// moved bytes, which is consumed; `options` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_err(
    this_: *const z_loaned_query_t,
    payload: *mut z_moved_bytes_t,
    options: *mut z_query_reply_err_options_t,
) -> ZResult {
    guarded(|| {
        // Consumed FIRST and on every path, as on the Put arm: upstream's
        // ownership transfer is unconditional.
        // SAFETY: the caller's contract.
        let taken = unsafe { crate::bytes::take_payload(payload) };
        let encoding = if options.is_null() {
            None
        } else {
            // SAFETY: the caller's contract — a `z_moved_*` field, taken before
            // any early return.
            unsafe { crate::encoding::take_moved_encoding((*options).encoding) }
        };

        // SAFETY: the caller's contract, delegated.
        let Some(marshal) = (unsafe { query_marshal(this_) }) else {
            return Z_ENULL;
        };
        let Some(payload) = taken else {
            return Z_ENULL;
        };
        marshal.push_reply(PendingReply::Err { payload, encoding });
        Z_OK
    })
}

/// The del-reply options' source info, on the arm that declares one.
///
/// # Safety
/// `options` must be a valid del-reply options struct.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
unsafe fn reply_del_source_info(
    options: *mut z_query_reply_del_options_t,
) -> Option<wz_runtime_tokio::sample::SourceInfo> {
    // SAFETY: the caller's contract.
    unsafe { crate::source_info::borrowed_source_info((*options).source_info) }
}

/// The no-unstable arm: upstream does not declare the field there.
///
/// # Safety
/// `options` is unused; the signature matches the sibling above.
#[cfg(feature = "zenoh-c-no-unstable-api")]
unsafe fn reply_del_source_info(
    _options: *mut z_query_reply_del_options_t,
) -> Option<wz_runtime_tokio::sample::SourceInfo> {
    None
}

/// Answer a query with a DELETE (zenoh-c `z_query_reply_del`).
///
/// The Del half of [`z_query_reply`], sharing its keyexpr-coverage gate and its
/// `ReplyMeta` flush so the two forms cannot answer differently about anything
/// but the kind. The owned options fields are consumed on every path, including
/// the error ones, exactly as on the Put side.
///
/// # Safety
/// `this_` must be null or a valid loaned query; `key_expr` must be null or a
/// valid loaned keyexpr; `options` must be null or a valid del-reply options
/// struct.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_del(
    this_: *const z_loaned_query_t,
    key_expr: *const z_loaned_keyexpr_t,
    options: *mut z_query_reply_del_options_t,
) -> ZResult {
    guarded(|| {
        let (attachment, timestamp, source_info) = if options.is_null() {
            (None, None, None)
        } else {
            // SAFETY: the caller's contract. Taken BEFORE any early return, so a
            // refused reply still consumes what upstream would have consumed.
            unsafe {
                (
                    crate::bytes::take_payload((*options).attachment),
                    crate::timestamp::timestamp_hint(
                        (*options).timestamp as *const std::ffi::c_void,
                    ),
                    reply_del_source_info(options),
                )
            }
        };

        // SAFETY: the caller's contract, delegated.
        let Some(marshal) = (unsafe { query_marshal(this_) }) else {
            return Z_ENULL;
        };
        // SAFETY: the caller's contract.
        let Some(ke) = (unsafe { keyexpr_str(key_expr) }) else {
            return Z_ENULL;
        };
        if !reply_keyexpr_is_covered(&marshal.keyexpr, ke, marshal.anyke) {
            return Z_EINVAL;
        }
        marshal.push_reply(PendingReply::Del {
            keyexpr: ke.to_owned(),
            attachment,
            timestamp,
            source_info,
        });
        Z_OK
    })
}

// --- the OWNED query --------------------------------------------------------

/// Mutably borrow an owned query (zenoh-c `z_query_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned query.
#[no_mangle]
pub unsafe extern "C" fn z_query_loan_mut(this_: *mut z_owned_query_t) -> *mut z_loaned_query_t {
    guard_val(std::ptr::null_mut(), || {
        if this_.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: the caller's contract.
        unsafe { (*this_).handle as *mut z_loaned_query_t }
    })
}

/// Deep-copy a borrowed query into an owned one (zenoh-c `z_query_clone`).
///
/// ## An ESCAPE, not merely a copy — and that is what makes it correct
///
/// Routed through [`escape_query`], the same path `z_fifo_channel_query_new`
/// takes, rather than through a plain field copy. The reason is the
/// `ResponseFinal`: a cloned query can be REPLIED to, so it must carry a
/// [`DeferredResponder`] and must count as an escape, or the terminator would go
/// out while the clone still holds an unanswered query and the querier would see
/// the replies truncated.
///
/// A query built OUTSIDE a dispatch has no face session and therefore cannot be
/// escaped; cloning one yields a gravestone rather than a value that would
/// silently fail to answer.
///
/// # Safety
/// `dst` must be null or valid and writable; `this_` must be null or a live
/// loaned query.
#[no_mangle]
pub unsafe extern "C" fn z_query_clone(dst: *mut z_owned_query_t, this_: *const z_loaned_query_t) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_query_t::null_value() };
        // SAFETY: the caller's contract, delegated.
        let handle = unsafe { escape_query(this_) };
        if !handle.is_null() {
            // SAFETY: as above.
            unsafe { *dst = z_owned_query_t::from_handle(handle) };
        }
    });
}

/// Take ownership of a mutably borrowed query (zenoh-c
/// `z_query_take_from_loaned`).
///
/// A COPY rather than a move, for the reason spelled out at
/// [`crate::sample::z_sample_take_from_loaned`] — and here the copy is
/// additionally the RIGHT shape, because it is an escape that takes its own
/// `ResponseFinal` hold. Stealing the borrowed marshal would leave the dispatch
/// with a marshal it still flushes replies from.
///
/// # Safety
/// `dst` must be null or valid and writable; `src` must be null or a live loaned
/// query.
#[no_mangle]
pub unsafe extern "C" fn z_query_take_from_loaned(
    dst: *mut z_owned_query_t,
    src: *mut z_loaned_query_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_query_clone(dst, src as *const z_loaned_query_t) };
}

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

    /// R311y554 — `allowed_origin` reaches the declaration, on every value,
    /// and `complete` still does. Both are asserted at the ONE seam that reads
    /// them, which is why the seam exists.
    #[test]
    fn queryable_options_carry_both_complete_and_allowed_origin() {
        use wz_runtime_tokio::locality::Locality;
        // A NULL pointer is upstream's defaults, not an error.
        // SAFETY: null is the documented "use defaults" input.
        let (complete, origin) = unsafe { queryable_declare_params(std::ptr::null()) };
        assert!(
            !complete,
            "z_queryable_options_default writes complete=false"
        );
        assert_eq!(
            origin,
            Locality::Any,
            "and allowed_origin = ZC_LOCALITY_ANY, which is what makes an \
             in-process z_get able to reach this session's own queryable"
        );

        for (c_value, expected) in [
            (crate::publisher::ZC_LOCALITY_ANY, Locality::Any),
            (
                crate::publisher::ZC_LOCALITY_SESSION_LOCAL,
                Locality::SessionLocal,
            ),
            (crate::publisher::ZC_LOCALITY_REMOTE, Locality::Remote),
        ] {
            for complete_in in [false, true] {
                let o = z_queryable_options_t {
                    complete: complete_in,
                    allowed_origin: c_value,
                };
                // SAFETY: a live local.
                let (complete, origin) = unsafe { queryable_declare_params(&o) };
                assert_eq!(complete, complete_in, "complete must not be disturbed");
                assert_eq!(
                    origin, expected,
                    "z_queryable_options_t.allowed_origin = {c_value} -> {expected:?}",
                );
            }
        }
    }

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

    /// R2261 — a `QueryView` whose source info is whatever the test hands it.
    ///
    /// Written here rather than reused from the pico side because the point is
    /// the SEAM: `QueryMarshal::new` reads `view.source_info()`, and a fake that
    /// left the accessor at its default `None` could never show the wiring.
    ///
    /// Gated with the three tests below: the accessor they grade does not exist
    /// on the no-unstable arms, so neither can a fixture built to reach it.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    struct SourcedQuery {
        source_info: Option<wz_runtime_tokio::sample::SourceInfo>,
    }

    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    impl QueryView for SourcedQuery {
        fn keyexpr(&self) -> &str {
            "demo/**"
        }
        fn parameters(&self) -> Option<&[u8]> {
            None
        }
        fn attachment(&self) -> Option<&[u8]> {
            None
        }
        fn source_info(&self) -> Option<&wz_runtime_tokio::sample::SourceInfo> {
            self.source_info.as_ref()
        }
        fn rid(&self) -> u64 {
            11
        }
        fn is_local(&self) -> bool {
            false
        }
    }

    /// The querier's `(zid, eid, sn)` reaches the C accessor.
    ///
    /// The three fields are asserted SEPARATELY and with distinct values: a
    /// marshal that carried the struct but converted it wrong — the zid
    /// re-padding is a real conversion, not a memcpy — would pass a test that
    /// only checked non-NULL.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    #[test]
    fn a_querys_source_info_reaches_the_c_accessor() {
        let view = SourcedQuery {
            source_info: Some(wz_runtime_tokio::sample::SourceInfo::new(&[9u8; 16], 5, 77)),
        };
        let mut marshal = QueryMarshal::new(&view);
        marshal.bind();
        let loaned = &marshal as *const QueryMarshal as *const z_loaned_query_t;
        // SAFETY: `loaned` aims at a live, bound marshal on this frame.
        let got = unsafe { z_query_source_info(loaned) };
        assert!(
            !got.is_null(),
            "a query that carried source info must not report NULL"
        );
        // SAFETY: non-null, and it borrows the marshal above.
        let si = unsafe { &*got };
        assert_eq!(si.zid, [9u8; 16]);
        assert_eq!(si.eid, 5);
        assert_eq!(si.sn, 77);
    }

    /// A query with no source-info ext reports NULL, not a zeroed struct.
    ///
    /// Upstream returns `Option<&z_source_info_t>`, so a C program checks the
    /// pointer; a zeroed struct would read as a real querier whose zid is
    /// sixteen zero bytes.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    #[test]
    fn a_query_without_source_info_reports_null() {
        let view = SourcedQuery { source_info: None };
        let mut marshal = QueryMarshal::new(&view);
        marshal.bind();
        let loaned = &marshal as *const QueryMarshal as *const z_loaned_query_t;
        // SAFETY: as above.
        assert!(unsafe { z_query_source_info(loaned) }.is_null());
    }

    /// An ESCAPED query keeps the querier's identity.
    ///
    /// ⚠ This drives the REAL `deep_copy_deferred`, and the first draft did
    /// not: it copied the two fields by hand into a struct literal, which
    /// asserts what the TEST wrote rather than what the escape path does. A
    /// `deep_copy_deferred` that set `source_info: None` would have passed it.
    /// The session comes from a real `SharedSession` for exactly that reason —
    /// the copy needs one, and a test that avoids needing one is avoiding the
    /// function it claims to grade.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    #[test]
    fn an_escaped_query_keeps_its_source_info() {
        let shared = wz_capi_core::faces::SharedSession::new(
            wz_runtime_tokio::runtime_impl::TokioTime::new(),
            vec![0x11; 16],
        )
        .expect("test host entropy");
        let view = SourcedQuery {
            source_info: Some(wz_runtime_tokio::sample::SourceInfo::new(&[4u8; 16], 1, 2)),
        };
        let borrowed = QueryMarshal::new(&view);
        let mut escaped = borrowed.deep_copy_deferred(shared.local_session().clone());
        escaped.bind();
        let loaned = &escaped as *const QueryMarshal as *const z_loaned_query_t;
        // SAFETY: `loaned` aims at a live, bound marshal on this frame.
        let got = unsafe { z_query_source_info(loaned) };
        assert!(!got.is_null(), "the escaped copy must carry it too");
        // SAFETY: non-null.
        assert_eq!(unsafe { &*got }.zid, [4u8; 16]);
        assert_eq!(unsafe { &*got }.eid, 1);
        assert_eq!(unsafe { &*got }.sn, 2);
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The QUERIER plane — a keyexpr plus get options bound to a session.
//!
//! A querier is exactly that in zenoh, in zenoh-pico and in wz, so
//! [`z_querier_get`] resolves its three ingredients from the declaration and
//! then calls the SAME `issue_get` `z_get` does.
//! Restating the body would have put the receive-side reply gate in two places,
//! and those two must agree or a reply is silently dropped.
//!
//! The matching listener is the querier's own: it watches for remote
//! QUERYABLES rather than subscribers, which is the one thing that differs from
//! the publisher's ([`crate::matching`]).

use std::ffi::{c_char, c_int};
// R311y563 — the cfg'd `c_void` import that used to live here is GONE, and the
// reason is worth one line: its only user was
// `z_querier_get_options_t::source_info`, which is typed
// `*mut z_moved_source_info_t` now that the source-info family exists. The
// y536 rule it illustrated ("a symbol's cfg is the OR of every arm that uses
// it") stands; this module simply has no such symbol any more.
use std::sync::{Arc, Mutex};

use wz_runtime_tokio::session::QueryOptions;

use crate::abi::{
    z_loaned_keyexpr_t, z_loaned_querier_t, z_loaned_session_t, z_moved_bytes_t,
    z_moved_closure_reply_t, z_moved_querier_t, z_owned_querier_t, Handle,
};
use crate::ffi::{guard_val, guarded};
use crate::get::{adopt_reply_closure, issue_get, z_query_consolidation_t};
use crate::keyexpr::keyexpr_str;
use crate::matching::{
    z_matching_status_t, z_moved_closure_matching_status_t, z_owned_closure_matching_status_t,
    CMatchClosure, MatchingHold,
};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::session::{session_handle, SessionHandle};

use wz_capi_core::faces::SharedSession;

/// zenoh-c `z_querier_options_t` (`zenoh_commons.h:702-728`) — 32 bytes on the
/// no-unstable oracle, 40 with `Z_FEATURE_UNSTABLE_API`.
///
/// Mirrored field for field, both arms, so rustc computes the size.
#[repr(C)]
pub struct z_querier_options_t {
    /// Reply target hint. CARRIED.
    pub target: c_int,
    /// Reply consolidation. CARRIED.
    pub consolidation: z_query_consolidation_t,
    /// Congestion control. R311y551 — HONOURED: declared once here and packed
    /// into every `z_querier_get`'s Request QoS ext.
    pub congestion_control: c_int,
    /// Express flag. R311y551 — HONOURED (bit 4 of the Request QoS byte).
    pub is_express: bool,
    /// Destination locality. R2947 — HONOURED: declared once here and
    /// inherited by every `z_querier_get`, as on `z_get`.
    pub allowed_destination: c_int,
    /// Which reply keyexprs are accepted — unstable-only.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub accept_replies: c_int,
    /// Priority. R311y551 — HONOURED (bits 0-2 of the Request QoS byte).
    pub priority: c_int,
    /// Timeout in milliseconds. CARRIED.
    pub timeout_ms: u64,
}

/// Fill default querier options (zenoh-c `z_querier_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_querier_options_default(this_: *mut z_querier_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_querier_options_t {
            target: crate::get::Z_QUERY_TARGET_BEST_MATCHING,
            consolidation: z_query_consolidation_t {
                mode: crate::get::Z_CONSOLIDATION_MODE_AUTO,
            },
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
            accept_replies: crate::get::ZC_REPLY_KEYEXPR_MATCHING_QUERY,
            priority: 5,
            timeout_ms: 0,
        }
    };
}

/// zenoh-c `z_querier_get_options_t`, mirrored field for field on both arms.
#[repr(C)]
pub struct z_querier_get_options_t {
    /// Query VALUE payload. CARRIED — consumed by [`z_querier_get`].
    pub payload: *mut z_moved_bytes_t,
    /// Value encoding for the query payload. R311y547 — READ, and carried in
    /// the Query value ext alongside the payload, the same as `z_get`'s.
    pub encoding: *mut crate::abi::z_moved_encoding_t,
    /// Querier source info — unstable-only. R311y563: READ and CONSUMED,
    /// stamped onto the outbound Query body's source_info ext.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub source_info: *const crate::source_info::z_source_info_t,
    /// Query attachment. CARRIED — consumed by [`z_querier_get`].
    pub attachment: *mut z_moved_bytes_t,
    /// Cancellation token — unstable-only, NEW at zenoh 1.10.0. R2949 —
    /// HONOURED and TAKEN on every path, as on [`crate::get::z_get_options_t`].
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub cancellation_token: *mut crate::cancellation::z_moved_cancellation_token_t,
}

/// R2949 — TAKE a querier-get's cancellation token, on the arm that has one.
///
/// # Safety
/// `options` must be a valid querier-get-options struct.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
unsafe fn querier_get_token(
    options: *mut z_querier_get_options_t,
) -> Option<Arc<wz_capi_core::cancellation::CancellationToken>> {
    // SAFETY: the caller's contract.
    unsafe { crate::cancellation::take_moved_cancellation_token((*options).cancellation_token) }
}

/// The no-unstable arm: the field does not exist.
///
/// # Safety
/// `options` is unused; the signature matches the sibling above.
#[cfg(feature = "zenoh-c-no-unstable-api")]
unsafe fn querier_get_token(
    _options: *mut z_querier_get_options_t,
) -> Option<Arc<wz_capi_core::cancellation::CancellationToken>> {
    None
}

/// Fill default per-get querier options (zenoh-c
/// `z_querier_get_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_querier_get_options_default(this_: *mut z_querier_get_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_querier_get_options_t {
            payload: std::ptr::null_mut(),
            encoding: std::ptr::null_mut(),
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: std::ptr::null_mut(),
            attachment: std::ptr::null_mut(),
            // Null, which is what upstream's own default writes: no token.
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            cancellation_token: std::ptr::null_mut(),
        }
    };
}

/// Behind a `z_owned_querier_t` handle: the keyexpr, the declared options, and
/// whatever matching listener the C side attached.
/// R311y563 — TAKE `z_querier_get_options_t::source_info`, on the arm that has
/// one.
///
/// A helper rather than an inline `#[cfg]` because the call sits inside a TUPLE
/// expression, where an attribute cannot go. Upstream gates the FIELD (it sits
/// behind `#if defined(Z_FEATURE_UNSTABLE_API)`), so on the no-unstable arm
/// there is nothing to take and `crate::source_info` is not compiled at all.
///
/// # Safety
/// `options` must be null or a valid querier-get-options struct.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
unsafe fn querier_get_source_info(
    options: *mut z_querier_get_options_t,
) -> Option<wz_runtime_tokio::sample::SourceInfo> {
    // SAFETY: the caller's contract.
    unsafe { crate::source_info::borrowed_source_info((*options).source_info) }
}

/// The no-unstable arm: the field does not exist, so the answer is always
/// `None`.
///
/// # Safety
/// `options` is unused; the signature matches the sibling above.
#[cfg(feature = "zenoh-c-no-unstable-api")]
unsafe fn querier_get_source_info(
    _options: *mut z_querier_get_options_t,
) -> Option<wz_runtime_tokio::sample::SourceInfo> {
    None
}

pub(crate) struct QuerierState {
    pub(crate) shared: Arc<SharedSession>,
    /// R311y568 — the declared keyexpr AND the loaned view `z_querier_keyexpr`
    /// hands back, in one holder so the accessor and the wire cannot disagree.
    pub(crate) keyexpr: crate::keyexpr::DeclaredKeyexpr,
    /// The per-declaration options every `z_querier_get` starts from.
    base: QueryOptions,
    /// A background matching listener, held so it is undeclared when the
    /// querier is. `Mutex` because the C side may attach one after declaring,
    /// from a different thread than the one that declared.
    matching: Mutex<Option<MatchingHold>>,
}

impl QuerierState {
    /// Whether only a COMPLETE queryable matches this querier: its target is `ALL_COMPLETE`,
    /// which is how zenoh's querier asks for its matching status and listener
    /// (`zenoh/src/api/querier.rs` @ `self.target == QueryTarget::AllComplete,`).
    pub(crate) fn matching_needs_complete(&self) -> bool {
        self.base.effective_target()
            == Some(wz_runtime_tokio::session_glue::QueryTarget::AllComplete)
    }

    /// Attach a matching listener, replacing (and so undeclaring) any previous.
    fn attach_matching(&self, hold: MatchingHold) {
        let mut slot = self.matching.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(hold);
    }
}

/// What the handle slot of a querier holds: a querier of the registry of faces, or, in a build
/// with `router-node`, one declared on a node.
pub(crate) enum QuerierHandle {
    /// A querier that fans its gets out through the faces of the registry.
    Registry(QuerierState),
    /// A querier that asks as the session of a node.
    #[cfg(feature = "router-node")]
    Node(NodeQuerier),
}

/// A querier declared on a node: the key it asks on and the options every get on it starts from,
/// and the node it asks through, held counted so that the querier can be used and dropped after
/// the session handle has been let go of.
#[cfg(feature = "router-node")]
pub(crate) struct NodeQuerier {
    node: Arc<wz_capi_core::drive::RouterState>,
    keyexpr: crate::keyexpr::DeclaredKeyexpr,
    base: QueryOptions,
    /// The id of the interest the querier declared on the node's data plane, which tells the
    /// querier's node the queryables beyond its router: what its matching reads.
    interest: u64,
    /// A background matching listener, retired with the querier.
    matching: Mutex<Option<MatchingHold>>,
}

#[cfg(feature = "router-node")]
impl NodeQuerier {
    /// The node the querier is declared on.
    pub(crate) fn node(&self) -> &Arc<wz_capi_core::drive::RouterState> {
        &self.node
    }

    /// The key the querier asks on.
    pub(crate) fn key(&self) -> &str {
        self.keyexpr.literal()
    }

    /// What the querier's matching counts: the queryables, only the complete ones when its
    /// target is `ALL_COMPLETE`, as zenoh's querier asks for its matching.
    pub(crate) fn plane(&self) -> wz_runtime_tokio::router_forward::MatchPlane {
        wz_runtime_tokio::router_forward::MatchPlane::Queryables {
            complete_required: self.base.effective_target()
                == Some(wz_runtime_tokio::session_glue::QueryTarget::AllComplete),
        }
    }

    /// Record a background matching listener, retiring any previous one.
    fn attach_matching(&self, hold: MatchingHold) {
        let mut slot = self.matching.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(hold);
    }
}

#[cfg(feature = "router-node")]
impl Drop for NodeQuerier {
    fn drop(&mut self) {
        self.node
            .forwarder()
            .undeclare_local_interest(self.interest, true);
    }
}

impl QuerierHandle {
    /// The key the querier asks on, as the cached view `z_querier_keyexpr` answers.
    fn loaned_keyexpr(&self) -> *const crate::abi::z_loaned_keyexpr_t {
        match self {
            Self::Registry(state) => state.keyexpr.as_loaned(),
            #[cfg(feature = "router-node")]
            Self::Node(node) => node.keyexpr.as_loaned(),
        }
    }
}

/// Read the handle behind a loaned querier.
///
/// # Safety
/// `this_` must be null or a valid loaned querier whose handle is live.
pub(crate) unsafe fn querier_handle<'a>(
    this_: *const z_loaned_querier_t,
) -> Option<&'a QuerierHandle> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<QuerierHandle>` this crate leaked.
    Some(unsafe { &*(handle as *const QuerierHandle) })
}

/// Declare a querier (zenoh-c `z_declare_querier`).
///
/// # Safety
/// `session` must be a valid loaned session; `querier` must be valid and
/// writable; `key_expr` must be a valid loaned keyexpr; `options` must be null
/// or valid.
#[no_mangle]
pub unsafe extern "C" fn z_declare_querier(
    session: *const z_loaned_session_t,
    querier: *mut z_owned_querier_t,
    key_expr: *const z_loaned_keyexpr_t,
    options: *mut z_querier_options_t,
) -> ZResult {
    guarded(|| {
        if querier.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, before any fallible work.
        // SAFETY: the caller's contract.
        unsafe { *querier = z_owned_querier_t::null_value() };

        // SAFETY: the caller's contract for both handles.
        let (Some(held), Some(ke)) = (unsafe { session_handle(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_EINVAL;
        }

        let base = if options.is_null() {
            QueryOptions::default()
        } else {
            // SAFETY: the caller's contract.
            querier_base(unsafe { &*options })
        };

        // A build without `router-node` holds the registry alone, and the match has the one arm.
        #[cfg_attr(
            not(feature = "router-node"),
            allow(clippy::infallible_destructuring_match)
        )]
        let mut boxed = Box::new(match held {
            SessionHandle::Registry(state) => QuerierHandle::Registry(QuerierState {
                shared: state.shared.clone(),
                keyexpr: crate::keyexpr::DeclaredKeyexpr::new(ke),
                base,
                matching: Mutex::new(None),
            }),
            // A node asks as its own face: the querier keeps the node and the options its gets
            // start from.
            #[cfg(feature = "router-node")]
            SessionHandle::Node(node) => {
                // The node holds the declarations of every face it serves, and its router tells
                // a peer below it a declaration only for an interest it holds: so a querier asks
                // for the queryables of its key, as the Rust API's node does.
                let interest = crate::matching::next_interest_id();
                node.forwarder().declare_local_interest(interest, &ke, true);
                QuerierHandle::Node(NodeQuerier {
                    node: Arc::clone(node),
                    keyexpr: crate::keyexpr::DeclaredKeyexpr::new(ke),
                    base,
                    interest,
                    matching: Mutex::new(None),
                })
            }
        });
        // Bind AFTER boxing — the state is at its final address only here.
        match &mut *boxed {
            QuerierHandle::Registry(state) => state.keyexpr.bind(),
            #[cfg(feature = "router-node")]
            QuerierHandle::Node(node) => node.keyexpr.bind(),
        }
        let handle = Box::into_raw(boxed) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *querier = z_owned_querier_t::from_handle(handle) };
        Z_OK
    })
}

/// Fold a `z_querier_options_t` into the query bundle every `z_querier_get`
/// on the handle starts from.
///
/// R2947 — lifted out of `z_declare_querier` so the fold is testable without a
/// session; the body is unchanged apart from the locality it now also folds.
fn querier_base(o: &z_querier_options_t) -> QueryOptions {
    let mut base = QueryOptions::default();
    {
        // SATURATE rather than wrap — a wrapped huge timeout becomes a tiny
        // one and expires every get immediately.
        base = base.with_timeout_ms(o.timeout_ms.min(u32::MAX as u64) as u32);
        if let Some(target) = crate::get::query_target_of(o.target) {
            base = base.with_target(target);
        }
        if let Some(mode) = crate::get::consolidation_of(o.consolidation.mode) {
            base = base.with_consolidation(mode);
        }
        // R311y551 — the request-side QoS trio, previously accepted and
        // ignored here exactly as on `z_get`. Declared ONCE on the querier
        // and inherited by every `z_querier_get`, which is upstream's shape:
        // `z_querier_get_options_t` carries no QoS fields at all, so the
        // per-get call has nothing to override them with.
        base = base
            .with_priority(crate::publisher::priority_from_c(o.priority))
            .with_congestion_control(crate::publisher::congestion_from_c(o.congestion_control))
            .with_express(o.is_express)
            // R2947 — and the destination locality, declared once here as
            // upstream's `z_declare_querier` does
            // (`zenoh-c/src/querier.rs` @ `.allowed_destination(options.allowed_destination.into())`).
            // Every `z_querier_get` then reaches `issue_get`, whose
            // local/remote split already honours it for `z_get`.
            .with_allowed_destination(crate::put::locality_from_c(o.allowed_destination));
    }
    base
}

/// Borrow a querier (zenoh-c `z_querier_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned querier.
#[no_mangle]
pub unsafe extern "C" fn z_querier_loan(
    this_: *const z_owned_querier_t,
) -> *const z_loaned_querier_t {
    this_ as *const z_loaned_querier_t
}

/// Mutably borrow a querier (zenoh-c `z_querier_loan_mut`).
///
/// A CAST, like its immutable twin.
///
/// # Safety
/// `this_` must be null or a valid owned querier.
#[no_mangle]
pub unsafe extern "C" fn z_querier_loan_mut(
    this_: *mut z_owned_querier_t,
) -> *mut z_loaned_querier_t {
    this_ as *mut z_loaned_querier_t
}

/// This querier's GLOBAL ENTITY ID (zenoh-c `z_querier_id`).
///
/// R311y568. UNSTABLE-gated — see [`crate::sub::z_subscriber_id`].
///
/// # Safety
/// `querier` must be null or a valid loaned querier.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_querier_id(
    querier: *const z_loaned_querier_t,
) -> crate::entity::z_entity_global_id_t {
    guard_val(crate::entity::z_entity_global_id_t::empty(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { querier_handle(querier) } {
            Some(QuerierHandle::Registry(state)) => {
                crate::entity::z_entity_global_id_t::for_entity(
                    &state.shared,
                    querier as *const std::ffi::c_void,
                )
            }
            #[cfg(feature = "router-node")]
            Some(QuerierHandle::Node(node)) => crate::entity::z_entity_global_id_t::for_entity_of(
                crate::zid::z_id_t::from_wire(node.node.zid()).id,
                querier as *const std::ffi::c_void,
            ),
            None => crate::entity::z_entity_global_id_t::empty(),
        }
    })
}

/// The keyexpr a querier was declared under (zenoh-c `z_querier_keyexpr`).
///
/// R311y568. Reads the querier's OWN `KeyexprState` — the same one
/// `z_querier_get` publishes against — rather than a second copy, so the
/// accessor and the wire cannot disagree about what was declared.
///
/// # Safety
/// `querier` must be null or a valid loaned querier.
#[no_mangle]
pub unsafe extern "C" fn z_querier_keyexpr(
    querier: *const z_loaned_querier_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { querier_handle(querier) } {
            Some(held) => held.loaned_keyexpr(),
            None => std::ptr::null(),
        }
    })
}

/// Issue one get through a querier (zenoh-c `z_querier_get`). Consumes the moved
/// closure on every path.
///
/// # Safety
/// `querier` must be null or a valid loaned querier; `parameters` must be null
/// or NUL-terminated; `callback` must be a valid moved reply closure; `options`
/// must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_querier_get(
    querier: *const z_loaned_querier_t,
    parameters: *const c_char,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_querier_get_options_t,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe {
        querier_get_with_selector(
            querier,
            crate::get::nul_terminated(parameters),
            callback,
            options,
        )
    }
}

/// R311y568 — [`z_querier_get`] with an explicit selector LENGTH (zenoh-c
/// `z_querier_get_with_parameters_substr`).
///
/// The querier twin of [`crate::get::z_get_with_parameters_substr`]; see there
/// for why the counted form is the general one.
///
/// # Safety
/// As [`z_querier_get`], except that `parameters` must be null or point at
/// `parameters_len` readable bytes rather than being NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_querier_get_with_parameters_substr(
    querier: *const z_loaned_querier_t,
    parameters: *const c_char,
    parameters_len: usize,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_querier_get_options_t,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe {
        querier_get_with_selector(
            querier,
            crate::get::counted_bytes(parameters, parameters_len),
            callback,
            options,
        )
    }
}

/// The body BOTH `z_querier_get` spellings share — one core, for the
/// consume-on-every-path reason [`crate::get`]'s records.
///
/// # Safety
/// As [`z_querier_get`], with `params` already read out of whichever selector
/// form the caller used.
unsafe fn querier_get_with_selector(
    querier: *const z_loaned_querier_t,
    params: Option<Vec<u8>>,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_querier_get_options_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // Adopt the closure FIRST (consume-on-all-paths): the C `drop(context)`
        // is the completion signal, so an early return correctly reports "this
        // get is over".
        // SAFETY: the caller's contract.
        let closure = unsafe { adopt_reply_closure(callback) };

        // The per-get moved payload / attachment are consumed on every path
        // too, matching upstream's unconditional ownership transfer.
        let ((payload, value), attachment, encoding, source_info, token) = if options.is_null() {
            ((None, None), None, None, None, None)
        } else {
            // SAFETY: the caller's contract.
            unsafe {
                (
                    crate::bytes::take_query_value((*options).payload),
                    crate::bytes::take_payload((*options).attachment),
                    crate::encoding::take_moved_encoding((*options).encoding),
                    querier_get_source_info(options),
                    querier_get_token(options),
                )
            }
        };

        // SAFETY: the caller's contract.
        let Some(held) = (unsafe { querier_handle(querier) }) else {
            return Z_ENULL;
        };
        let base = match held {
            QuerierHandle::Registry(state) => &state.base,
            #[cfg(feature = "router-node")]
            QuerierHandle::Node(node) => &node.base,
        };
        let mut opts = base.clone();
        if let Some(payload) = payload {
            opts = opts.with_payload(payload);
        }
        if let Some(encoding) = encoding {
            opts = opts.with_encoding(encoding);
        }
        if let Some(attachment) = attachment {
            opts = opts.with_attachment(attachment);
        }
        if let Some(info) = source_info {
            opts = opts.with_source_info(info);
        }
        // A build without `router-node` holds the registry alone, and the match has the one arm.
        #[cfg_attr(
            not(feature = "router-node"),
            allow(clippy::infallible_destructuring_match)
        )]
        let state = match held {
            QuerierHandle::Registry(state) => state,
            #[cfg(feature = "router-node")]
            QuerierHandle::Node(node) => {
                // The node was closed with its session: a get on it is not asked and not left
                // waiting for an answer that cannot come.
                if node.node.is_closed() {
                    return crate::result::Z_ESESSION_CLOSED;
                }
                return crate::get::issue_get_on_node(
                    &node.node,
                    node.keyexpr.literal().to_owned(),
                    params,
                    opts,
                    value,
                    closure,
                    token,
                );
            }
        };
        issue_get(
            &state.shared,
            state.keyexpr.literal().to_owned(),
            params,
            opts,
            value,
            closure,
            token,
        )
    })
}

/// Declare a background matching listener on a querier (zenoh-c
/// `z_querier_declare_background_matching_listener`). Consumes the moved closure
/// on every path.
///
/// The querier's listener watches for remote QUERYABLES, which is the one thing
/// that differs from the publisher's — everything below it (the cross-face OR,
/// the serialised delivery) is the shared registry path.
///
/// # Safety
/// `querier` must be null or a valid loaned querier; `callback` must be a valid
/// moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_querier_declare_background_matching_listener(
    querier: *const z_loaned_querier_t,
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
        let Some(held) = (unsafe { querier_handle(querier) }) else {
            return Z_ENULL;
        };
        let closure = Arc::new(cclosure);
        let sink: Arc<dyn Fn(bool) + Send + Sync> = Arc::new(move |matching: bool| {
            let Some(call) = closure.call else {
                return;
            };
            let status = z_matching_status_t { matching };
            let ctx = closure.context.0;
            // SAFETY: `call` is the C callback and `status` outlives it. An
            // unwind out of the callback across `extern "C"` is UB, so it is
            // caught — the drive loop survives a misbehaving callback.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                call(&status, ctx);
            }));
        });
        match held {
            QuerierHandle::Registry(state) => {
                let id = state.shared.declare_querier_matching_listener(
                    state.keyexpr.literal().to_owned(),
                    sink,
                    state.matching_needs_complete(),
                );
                state.attach_matching(MatchingHold::new(state.shared.clone(), id));
            }
            // A node's own face is told whether anything of the queryables matches the key.
            #[cfg(feature = "router-node")]
            QuerierHandle::Node(node) => {
                let id = node.node().watch_matching(
                    node.plane(),
                    node.key(),
                    wz_runtime_tokio::locality::Locality::Any,
                    Box::new(move |matching| sink(matching)),
                );
                node.attach_matching(MatchingHold::node(Arc::clone(node.node()), id));
            }
        }
        Z_OK
    })
}

/// `true` iff the owned querier holds a live handle (zenoh-c
/// `z_internal_querier_check`).
///
/// # Safety
/// `this_` must be null or a valid owned querier.
#[no_mangle]
pub unsafe extern "C" fn z_internal_querier_check(this_: *const z_owned_querier_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned querier (zenoh-c `z_internal_querier_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned querier.
#[no_mangle]
pub unsafe extern "C" fn z_internal_querier_null(this_: *mut z_owned_querier_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_querier_t::null_value() };
    }
}

/// Undeclare a querier (zenoh-c `z_undeclare_querier`) — which also releases
/// any matching listener it carries.
///
/// # Safety
/// `this_` must be null or a valid moved querier.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_querier(this_: *mut z_moved_querier_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<QuerierHandle>` this crate leaked; dropping it
            // drops the `MatchingHold`, which undeclares the listener.
            drop(unsafe { Box::from_raw(handle as *mut QuerierHandle) });
            unsafe { (*this_)._this = z_owned_querier_t::null_value() };
        }
        Z_OK
    })
}

/// Drop a querier (zenoh-c `z_querier_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved querier.
#[no_mangle]
pub unsafe extern "C" fn z_querier_drop(this_: *mut z_moved_querier_t) {
    // SAFETY: delegated — the slot is nulled, so a double drop is a no-op.
    let _ = unsafe { z_undeclare_querier(this_) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R2947 — the querier's declared `allowed_destination` reaches the bundle
    /// every `z_querier_get` starts from. Before R2947 it was accepted and
    /// ignored, so every non-default value here resolved to `Any`.
    #[test]
    fn a_querier_carries_its_declared_allowed_destination() {
        use wz_runtime_tokio::locality::Locality;
        for (c_value, expected) in [
            (crate::publisher::ZC_LOCALITY_ANY, Locality::Any),
            (
                crate::publisher::ZC_LOCALITY_SESSION_LOCAL,
                Locality::SessionLocal,
            ),
            (crate::publisher::ZC_LOCALITY_REMOTE, Locality::Remote),
        ] {
            let mut o = z_querier_options_t {
                target: 0,
                consolidation: z_query_consolidation_t { mode: 0 },
                congestion_control: 0,
                is_express: false,
                allowed_destination: 0,
                #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
                accept_replies: 0,
                priority: 0,
                timeout_ms: 0,
            };
            // SAFETY: a live local.
            unsafe { z_querier_options_default(&mut o) };
            o.allowed_destination = c_value;
            assert_eq!(
                querier_base(&o).allowed_destination,
                expected,
                "z_querier_options_t.allowed_destination = {c_value}",
            );
        }
    }

    /// The two options structs default to what upstream's do, and both timeouts
    /// start at 0 meaning "resolve the default".
    #[test]
    fn the_querier_options_defaults_match_upstreams() {
        let mut opts = z_querier_options_t {
            target: 99,
            consolidation: z_query_consolidation_t { mode: 99 },
            congestion_control: 99,
            is_express: true,
            allowed_destination: 99,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            accept_replies: 99,
            priority: 99,
            timeout_ms: 99,
        };
        // SAFETY: live locals.
        unsafe { z_querier_options_default(&mut opts) };
        assert_eq!(opts.target, crate::get::Z_QUERY_TARGET_BEST_MATCHING);
        assert_eq!(
            opts.consolidation.mode,
            crate::get::Z_CONSOLIDATION_MODE_AUTO
        );
        assert_eq!(opts.timeout_ms, 0);

        let mut get_opts = z_querier_get_options_t {
            payload: 1 as *mut z_moved_bytes_t,
            encoding: 1 as *mut crate::abi::z_moved_encoding_t,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: 1 as *const crate::source_info::z_source_info_t,
            attachment: 1 as *mut z_moved_bytes_t,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            cancellation_token: 1 as *mut crate::cancellation::z_moved_cancellation_token_t,
        };
        // SAFETY: live locals.
        unsafe { z_querier_get_options_default(&mut get_opts) };
        assert!(get_opts.payload.is_null());
        assert!(get_opts.attachment.is_null());
        #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
        assert!(get_opts.cancellation_token.is_null());
    }

    /// Every export answers a NULL without dereferencing it.
    #[test]
    fn the_querier_exports_answer_null_without_dereferencing_it() {
        // SAFETY: passing NULL is exactly what these guards exist for.
        unsafe {
            assert!(!z_internal_querier_check(std::ptr::null()));
            assert_eq!(
                z_querier_get(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut()
                ),
                Z_ENULL
            );
            assert_eq!(
                z_querier_declare_background_matching_listener(
                    std::ptr::null(),
                    std::ptr::null_mut()
                ),
                Z_ENULL
            );
            assert_eq!(z_undeclare_querier(std::ptr::null_mut()), Z_OK);
            z_querier_drop(std::ptr::null_mut());
        }
    }
}

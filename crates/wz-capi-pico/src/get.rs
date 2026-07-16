// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The get (querier) half of the pico query plane: `z_closure_reply`,
//! `z_get` / `z_get_with_parameters_substr`, `z_get_options_t`, and the
//! loaned-reply accessors.
//!
//! The responder half is [`crate::query`]; this is its querier twin. A C `z_get`
//! fans ONE wz `Session::query` per connected face (pico's "a get goes to the
//! session's whole peer set") and threads every face's replies back into the one
//! C reply closure.
//!
//! ## Completion is the `Arc` refcount, and nothing else
//!
//! pico signals a get's completion by running the reply closure's
//! `drop(context)` once, when no further reply can arrive
//! (`_z_query`/`_z_trigger_query_reply_final`, and `_z_drop_handler_execute`
//! directly when `remaining_finals == 0`, `src/net/primitives.c:560-562`). Here
//! that signal is carried by the refcount of the shared
//! [`Arc<CReplyClosure>`][CReplyClosure]: each face's pending query holds a
//! clone through its `on_reply` closure, and the last release runs
//! [`crate::ffi::CClosure`]'s `Drop` → the C `drop(context)`.
//!
//! An N-finals COUNTER — the obvious alternative — is not merely inelegant, it
//! is WRONG here, and the difference is a hang. A face that dies mid-flight
//! takes its whole `ReplyRegistry` down with it: its pending entry is DROPPED,
//! never swept, so it fires no final and a counter waiting for it never reaches
//! zero. The refcount handles that case (the dropped entry drops the closure,
//! releasing the clone) with the same code path as a real final, a timeout
//! sweep, a per-face issue error, and the zero-faces get. It is also PROMPT: no
//! path has to wait for a deadline to conclude the get is over.
//!
//! The C thread therefore holds its OWN clone across the whole fan loop. Without
//! it, face 1 answering (and its entry dropping) before face 2's `query` is
//! issued would take the refcount to zero and complete the get early.
//!
//! ## CONSOLIDATION — the gap is CLOSED, and one divergence remains (R311y321)
//!
//! **RETRACTED.** Everything this section said before R311y321 rested on
//! "`consolidation` is transmitted on the wire and has NO client-side effect
//! here", and that is no longer true. `wz-session-core::reply_sink` now carries
//! an `alloc`-gated `ConsolidatingSink<S: ReplySink>` decorator on the
//! R311gb-3c [`ReplySink`][wz_session_core::reply_sink::ReplySink] seam, and
//! `Session::query` installs it with the query's own mode. The old text is not
//! amended in place because it was load-bearing in the wrong direction: it told
//! the reader NOT to trust the mode.
//!
//! What is true now:
//!
//! - **LATEST works, and that closes the C API's DEFAULT path.**
//!   `z_get_options_default` is `Z_CONSOLIDATION_MODE_AUTO`
//!   (`vendor/zenoh-pico/src/api/api.c:1725` -> `:462` -> `:446`); this crate
//!   resolves AUTO -> LATEST exactly as pico's `primitives.c:567-573` does
//!   (`_time=` in the selector -> NONE, else LATEST); wz caches per keyexpr and
//!   flushes at the terminal final, as pico does (`query.c:143-172` stores,
//!   `:239-247` flushes). A stock `z_get` against two queryables answering ONE
//!   key now delivers **one** reply through this crate, as it does through pico.
//!
//! - **MONOTONIC now DIVERGES from pico, deliberately.** wz suppresses a stale
//!   reply — it forwards only when the arrival is at least as recent as the last
//!   one forwarded for that keyexpr. **pico forwards every reply under
//!   MONOTONIC**: its `drop` flag gates only the cache store, never the callback
//!   at `query.c:179` (`if (_consolidation != Z_CONSOLIDATION_MODE_LATEST)
//!   callback(...)`), which makes pico's MONOTONIC observably identical to NONE
//!   and its cache dead weight. wz follows ZENOH here
//!   (`zenoh-1.5.0/src/api/session.rs`, the `ConsolidationMode::Monotonic` arm
//!   returns no callback for a stale reply).
//!
//!   The pre-y321 text asserted "`MONOTONIC` is NOT part of this gap ... wz
//!   matches" — true when wz applied nothing, and now false BY CHOICE. A C
//!   caller that relinks a pico app against wz and uses
//!   `Z_CONSOLIDATION_MODE_MONOTONIC` will see stale replies suppressed where
//!   pico delivered them. The wire is unaffected (both emit the MONOTONIC byte;
//!   pico's encode predicate is `_consolidation != Z_CONSOLIDATION_MODE_DEFAULT`,
//!   `codec/message.c:402-412`).
//!
//!   **Why diverge rather than mirror.** Preserving pico's behaviour needs the
//!   wire ext and the local mode to be settable INDEPENDENTLY — pico puts
//!   MONOTONIC on the wire, so "pico-faithful" means wire=MONOTONIC with no
//!   local effect, which `with_consolidation` cannot express. That would mean a
//!   new public axis on `QueryOptions` existing solely for this quirk, to
//!   preserve what reads as an upstream bug (the `drop` pico computes and then
//!   ignores). wz's north star is a zenoh+pico SUPERSET, not a pico mirror: a
//!   MONOTONIC that cannot suppress anything is a mode in name only. Named here
//!   rather than silently absorbed.
//!
//! no-alloc LATEST is a NAMED NON-divergence rather than a gap: pico's cache is
//! unbounded HEAP (`~/zenoh-pico/src/collections/list.c:262`), so there is no
//! no-alloc design to port — pico's "MCU" profile has an allocator and wz's
//! no-alloc profile is a strictly stronger target the reference never had.
//!
//! The inventory's `query-consolidation` atom claimed `C=indep reply dedup`;
//! R311y296 corrected that reason to say what is actually built (the Q_C wire
//! ext) and what is not, rather than leave the SSOT asserting a behaviour no
//! code implements. The atom stays `active` — that is right on the A3 invariant,
//! since the ext IS a real cfg knob gating real code — because the A3 grammar
//! has no "active but half-built" tag (its `PARTIAL` tag requires `reserved`,
//! and a reserved atom must have zero cfg sites, which this one does not). The
//! honesty therefore lives in the reason's prose and here, not in a status flip.
//!
//! ## What is deliberately NOT exported, and why that is loud
//!
//! Same principle as the responder half: a symbol this round cannot honour is
//! withheld so the C program fails at LINK time rather than silently misbehaving.
//!
//! - The **owned-reply family** (`z_reply_clone` / `z_reply_take_from_loaned` /
//!   the `z_owned_reply_t` ownership set) — pico's channel handlers
//!   (`include/zenoh-pico/api/handlers.h`, e.g. `z_fifo_channel_reply_new`) are
//!   `static inline` and call it, so exporting it without the retained-reply
//!   seam would make every channel-based get compile, link, and then silently
//!   drop its replies. Same argument, same seam, as the owned-QUERY family.
//! - `z_reply_err_encoding` → `z_loaned_encoding_t` (the encoding family this
//!   round does not build).
//!
//! `z_reply_replier_id` looks like a third but is not: it is
//! `#ifdef Z_FEATURE_UNSTABLE_API` (`primitives.h:2720-2731`) and that flag
//! defaults to 0 (`~/zenoh-pico/CMakeLists.txt:316`), so a default build has no
//! such symbol to match — the same reason `z_queryable_id` was not a gap in R3a.
//!
//! The **querier family** (`z_declare_querier` / `z_querier_get`) is withheld
//! and NAMED: it is not a bound get. pico's querier owns a DECLARED entity —
//! `_z_declare_querier` emits a `Declare(DeclareQuerier)` so matching queryables
//! learn of it ahead of any query, and `z_querier_get` reuses that declaration's
//! id. wz has no querier declaration to bind (no `DeclareQuerier` emit path), so
//! mapping it onto a repeated `z_get` would produce a querier that never
//! declares — observably different on the wire for anything watching matching
//! status. That is a real seam, not a cost, and it is a follow-up round.

use std::ffi::{c_int, c_void};
use std::sync::Arc;

use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::reply_sink::{ReplyKind, ReplyView};
use wz_runtime_tokio::session::QueryOptions;
use wz_runtime_tokio::session_glue::{ConsolidationMode, QueryTarget};

use crate::abi::{z_loaned_bytes_t, z_loaned_keyexpr_t, z_moved_bytes_t};
use crate::faces::SharedSession;
use crate::ffi::{guard_val, guarded, CClosure as FfiClosure};
use crate::keyexpr::keyexpr_str;
use crate::pubsub::{
    sample_kind_of, z_closure_drop_callback_t, z_loaned_sample_t, SampleMarshal, Z_SAMPLE_KIND_PUT,
};
use crate::query::{parameters_has_anyke, z_reply_keyexpr_t, ANYKE_PARAM, PARAM_SEPARATOR};
use crate::result::{ZResult, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
use crate::session::{session_state, z_loaned_session_t};

// --- pico enum-typed option fields -----------------------------------------

/// pico `z_query_target_t` (`api/constants.h:262-266`): which queryables a get
/// should reach. A plain C enum, so it occupies an `int`.
pub type z_query_target_t = c_int;
/// pico `Z_QUERY_TARGET_BEST_MATCHING` = 0 (`constants.h:262`), also
/// `Z_QUERY_TARGET_DEFAULT`.
pub const Z_QUERY_TARGET_BEST_MATCHING: z_query_target_t = 0;
/// pico `Z_QUERY_TARGET_ALL` = 1 (`constants.h:263`).
pub const Z_QUERY_TARGET_ALL: z_query_target_t = 1;
/// pico `Z_QUERY_TARGET_ALL_COMPLETE` = 2 (`constants.h:264`).
pub const Z_QUERY_TARGET_ALL_COMPLETE: z_query_target_t = 2;

/// pico `z_consolidation_mode_t` (`api/constants.h:184-189`).
pub type z_consolidation_mode_t = c_int;
/// pico `Z_CONSOLIDATION_MODE_AUTO` = **-1** (`constants.h:184`), also
/// `Z_CONSOLIDATION_MODE_DEFAULT`. Negative, hence the signed `int`.
pub const Z_CONSOLIDATION_MODE_AUTO: z_consolidation_mode_t = -1;
/// pico `Z_CONSOLIDATION_MODE_NONE` = 0 (`constants.h:185`).
pub const Z_CONSOLIDATION_MODE_NONE: z_consolidation_mode_t = 0;
/// pico `Z_CONSOLIDATION_MODE_MONOTONIC` = 1 (`constants.h:186`).
pub const Z_CONSOLIDATION_MODE_MONOTONIC: z_consolidation_mode_t = 1;
/// pico `Z_CONSOLIDATION_MODE_LATEST` = 2 (`constants.h:187`).
pub const Z_CONSOLIDATION_MODE_LATEST: z_consolidation_mode_t = 2;

/// pico `z_query_consolidation_t` (`api/types.h:215-217`) — a one-field struct
/// wrapping the mode, not a bare enum.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_query_consolidation_t {
    pub mode: z_consolidation_mode_t,
}

/// pico `Z_GET_TIMEOUT_DEFAULT` = 10000 ms
/// (`~/zenoh-pico/include/zenoh-pico/config.h.in:208`).
///
/// Load-bearing, and NOT interchangeable with "no timeout": pico's `z_get`
/// rewrites `timeout_ms == 0` to this value before issuing
/// (`src/api/api.c:1762-1764`), so in pico 0 means "default", never "infinite".
///
/// R311y326 — wz now agrees on this build. `QueryOptions::effective_timeout_ms`
/// resolves `timeout_ms == 0` to `DEFAULT_QUERY_TIMEOUT_MS`, and this crate
/// composes `query-timeout` (Cargo.toml), so C's `0` would resolve to the same
/// 10s whether or not [`get_timeout_ms`] rewrote it. This doc previously said
/// wz's `0` meant the OPPOSITE (never-expire, leaking the pending entry) — that
/// held only before y326 and only on a `query-timeout`-off build. The rewrite in
/// [`get_timeout_ms`] is now belt-and-suspenders on this build; see there for
/// the half that is still load-bearing (the `u64 -> u32` saturation).
pub const Z_GET_TIMEOUT_DEFAULT: u64 = 10_000;

// --- opaque loaned reply ---------------------------------------------------

/// Opaque loaned reply (pico `z_loaned_reply_t`). The C callback holds only a
/// pointer and passes it back to the accessors, so this stays opaque rather
/// than reproducing pico's concrete `_z_reply_t` layout — the model
/// `z_loaned_sample_t` / `z_loaned_query_t` already use.
#[repr(C)]
pub struct z_loaned_reply_t {
    _opaque: [u8; 0],
}

/// Opaque loaned reply error (pico `z_loaned_reply_err_t`), what `z_reply_err`
/// hands back.
#[repr(C)]
pub struct z_loaned_reply_err_t {
    _opaque: [u8; 0],
}

/// The owned marshal behind a borrowed `z_loaned_reply_t` during one callback.
///
/// Owns copies of the reply's bytes so they outlive the wz [`ReplyView`] borrow.
/// The Ok arm reuses [`SampleMarshal`] because `z_reply_ok` must hand back a
/// `z_loaned_sample_t` — so the sample accessors serve this plane unchanged.
///
/// Valid for exactly the duration of one `call`, the same scope pico gives its
/// own loaned reply. Using the pointer afterwards, or from another thread, is
/// undefined behaviour in pico too (its loaned reply is only escapable via
/// `z_reply_take_from_loaned`, the owned family this round withholds). No
/// tripwire is added for that, for the reason [`crate::query::QueryMarshal`]
/// records: after the frame dies, READING a validity flag is itself the
/// use-after-free it was meant to intercept.
struct ReplyMarshal {
    is_ok: bool,
    /// The Put/Del body, present iff [`Self::is_ok`].
    sample: SampleMarshal,
    /// The Err blob, meaningful iff `!is_ok`.
    err_payload: Vec<u8>,
    loaned_err_payload: z_loaned_bytes_t,
}

impl ReplyMarshal {
    /// Build the marshal for one inbound reply, cached views still UNBOUND —
    /// [`Self::bind`] must run at the final address (see [`SampleMarshal::bind`]).
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
            // Only Put/Del reach a sample; the Err arm's value is inert (the C
            // side must gate on `z_reply_is_ok` before `z_reply_ok`).
            ReplyKind::Del => sample_kind_of(wz_runtime_tokio::sample::SampleKind::Del),
            _ => Z_SAMPLE_KIND_PUT,
        };
        Self {
            is_ok,
            sample: SampleMarshal::new(view.keyexpr().to_owned(), sample_payload, sample_kind),
            err_payload,
            loaned_err_payload: z_loaned_bytes_t {
                handle: std::ptr::null_mut(),
                _pad: [std::ptr::null_mut(); 3],
            },
        }
    }

    /// Point every cached view at this marshal's own fields. MUST run only once
    /// the marshal sits at its FINAL address — `loaned_err_payload.handle`
    /// stores the address of the `Vec` STRUCT, which moves with the struct.
    fn bind(&mut self) {
        self.sample.bind();
        self.loaned_err_payload.handle = &self.err_payload as *const Vec<u8> as *mut c_void;
    }
}

/// Read the marshal behind a loaned reply, or `None` if the pointer is null.
///
/// # Safety
/// `reply` must be null or a pointer this crate handed to a reply callback.
unsafe fn reply_marshal<'a>(reply: *const z_loaned_reply_t) -> Option<&'a ReplyMarshal> {
    if reply.is_null() {
        return None;
    }
    Some(&*(reply as *const ReplyMarshal))
}

/// Read the marshal behind a loaned reply ERROR. `z_reply_err` hands back the
/// same marshal address re-typed, so this is the mirror of [`reply_marshal`].
///
/// # Safety
/// `err` must be null or a pointer this crate handed back from `z_reply_err`.
unsafe fn reply_err_marshal<'a>(err: *const z_loaned_reply_err_t) -> Option<&'a ReplyMarshal> {
    if err.is_null() {
        return None;
    }
    Some(&*(err as *const ReplyMarshal))
}

// --- C closure types -------------------------------------------------------

/// pico `z_closure_reply_callback_t`: `void call(z_loaned_reply_t*, void*)`
/// (`session/session.h:159`, aliased at `api/types.h:743`).
///
/// The reply pointer is NON-const, unlike the query plane's — pico's own example
/// signs it `void reply_handler(z_loaned_reply_t *reply, void *ctx)`
/// (`examples/unix/c11/z_get.c:35`). The accessors still take `const`, so the
/// mutability is nominal, but the callback typedef must match or a C compiler
/// rejects the assignment.
pub type z_closure_reply_callback_t =
    Option<unsafe extern "C" fn(*mut z_loaned_reply_t, *mut c_void)>;

/// Owned reply closure (pico `z_owned_closure_reply_t`, 24 B:
/// `{ context, call, drop }` in that field order — `api/types.h:745-749`).
#[repr(C)]
pub struct z_owned_closure_reply_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_reply_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Loaned reply closure (pico `z_loaned_closure_reply_t`), same layout.
#[repr(C)]
pub struct z_loaned_closure_reply_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_reply_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved reply closure (pico `z_moved_closure_reply_t`).
#[repr(C)]
pub struct z_moved_closure_reply_t {
    pub(crate) _this: z_owned_closure_reply_t,
}

impl z_owned_closure_reply_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

/// The Rust-side wrapper one C get's per-face reply callbacks share — the
/// querier plane's instantiation of the shared [`crate::ffi::CClosure`]
/// mechanism. Its `Drop` invokes the C `drop(context)` exactly once, when the
/// last face's pending query and the C thread's own fan-loop guard have released
/// it. That drop IS the get's completion signal (see the module doc).
pub(crate) type CReplyClosure = FfiClosure<z_closure_reply_callback_t>;

// SAFETY: the querier plane's own argument, written here rather than granted by
// a blanket impl on the generic (see `crate::ffi::CClosure`). It is genuinely
// different from the sample / query planes' and must not be paraphrased from
// them — in particular the "drive-task-only" phrasing they use is FALSE here.
//
// Sharing one get's `CReplyClosure` across per-face callbacks needs `Sync` (so
// `Arc<CReplyClosure>`, and each `on_reply`, is `Send`).
//
// `call` — invoked only from the drive thread. Every face of a session is driven
// on ONE task, and `on_reply` runs at a `drain_deferred_fires` site. The one
// drain site reachable from the C APPLICATION thread is `Session::query`'s own
// tail, which is gated on `allows_local` (`session/mod.rs:2023`) — and
// `get_options` below pins `Locality::Remote`, so that gate is closed and the
// C-thread `z_get` drains nothing. The `Remote` pin is what makes this
// MECHANICAL rather than a promise: `Any::allows_local()` is true
// (`wz-session-core/src/locality.rs:70-72`), so a default-locality get would
// drain on the C thread while a drive thread ran `call` for another face — two
// `call(context)`s at once on one C context, the unsound-`Sync` bug R311y288
// fixed on the publish plane. The sibling half of the same argument lives on
// `faces::queryable_options` (the queryable is Remote too, so no in-process
// queryable job can be staged for a C-thread drain either), and
// `SharedSession::dispatch` is the only caller of the UNGATED
// `sweep_expired_queries`.
//
// `drop` — CANNOT be attributed to the drive thread, and this is where the
// querier plane genuinely diverges from its siblings. It runs wherever the LAST
// `Arc` clone is released, which is the drive thread for a real final / timeout
// sweep / face death, but the C thread for a get that issued no live query at
// all (zero faces, or every face's `query` erroring at issue). That is sound,
// and pico-faithful: pico likewise runs the drop handler on the CALLING thread
// when `remaining_finals == 0` (`src/net/primitives.c:560-562`). The
// serialization is the refcount itself — a live `call` holds a clone through its
// `on_reply`, so the refcount cannot reach zero while one is running, on either
// thread.
unsafe impl Sync for CReplyClosure {}

/// The querier-side `accept_replies` gate — pico's
/// `if (!pen_qry->_anyke && !_z_keyexpr_intersects(&pen_qry->_key, keyexpr))`
/// -> discard the reply (`~/zenoh-pico/src/session/query.c:121-127`).
///
/// This is the RECEIVE half of `accept_replies`, and it is on by default:
/// `_anyke` is false unless the caller asked for `Z_REPLY_KEYEXPR_ANY`
/// (`primitives.c:575-578`), and the default is `Z_REPLY_KEYEXPR_MATCHING_QUERY`
/// (`api/constants.h:291`). [`transmit_parameters`] is the SEND half; a getter
/// with only the send half would still surface a reply on a key disjoint from
/// its query, which pico silently drops.
///
/// It matters precisely because this crate is a drop-in against FOREIGN peers:
/// R3a's responder already enforces `reply ⊆ query` before emitting
/// ([`crate::query::z_query_reply`]), so a wz↔wz deployment never exercises this
/// — but a real pico/zenoh peer is exactly what pico defends against here, and
/// it is the deployment the crate exists for.
///
/// Routed through the SAME intersection SSOT the responder side uses
/// ([`crate::query::reply_keyexpr_is_covered`]) rather than re-derived, so the
/// two halves cannot drift apart.
struct ReplyGate {
    /// The keyexpr the get asked under — pico's `pen_qry->_key`.
    query_keyexpr: String,
    /// pico's `pen_qry->_anyke`: set when the caller passed
    /// `Z_REPLY_KEYEXPR_ANY` OR wrote `_anyke` into the selector itself
    /// (`primitives.c:575-578` ORs the two).
    anyke: bool,
}

/// Fire the C reply callback for one inbound reply on one face.
///
/// Marshals the wz [`ReplyView`] into a borrowed `z_loaned_reply_t` and invokes
/// `call`. The marshal is valid only for that call — pico's contract, which is
/// why the C side must copy anything it keeps.
fn fire_reply(closure: &CReplyClosure, gate: &ReplyGate, view: &dyn ReplyView) {
    let call = match closure.call {
        Some(f) => f,
        None => return,
    };
    // pico drops a reply the query does not accept BEFORE building it
    // (`query.c:121-127`) — the callback never sees it.
    if !crate::query::reply_keyexpr_is_covered(&gate.query_keyexpr, view.keyexpr(), gate.anyke) {
        return;
    }
    let mut marshal = ReplyMarshal::new(view);
    // Bind AFTER the move out of `new` — final address only here.
    marshal.bind();
    let reply_ptr = &mut marshal as *mut ReplyMarshal as *mut z_loaned_reply_t;
    // SAFETY: `call` is the C callback; `marshal` outlives it and the borrowed
    // reply is valid only for its duration (pico contract). A panic unwinding
    // OUT of the C callback across this `extern "C"` boundary is UB and would
    // tear down the drive thread, so it is caught here.
    let ctx = closure.context.0;
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        call(reply_ptr, ctx);
    }));
}

// --- closure_reply exports -------------------------------------------------

/// Build an owned reply closure from a callback + drop + context (pico
/// `z_closure_reply`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_reply(
    closure: *mut z_owned_closure_reply_t,
    call: z_closure_reply_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        if closure.is_null() {
            return Z_ERR_NULL;
        }
        *closure = z_owned_closure_reply_t {
            context,
            call,
            drop,
        };
        Z_OK
    })
}

/// Invoke a reply closure directly (pico `z_closure_reply_call`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_reply_call(
    closure: *const z_loaned_closure_reply_t,
    reply: *mut z_loaned_reply_t,
) {
    let _ = guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        if let Some(call) = (*closure).call {
            call(reply, (*closure).context);
        }
        Z_OK
    });
}

/// Zero an owned reply closure (pico `z_internal_closure_reply_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_reply_null(closure: *mut z_owned_closure_reply_t) {
    if !closure.is_null() {
        *closure = z_owned_closure_reply_t::null_value();
    }
}

/// `true` iff the closure holds a callback (pico
/// `z_internal_closure_reply_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_reply_check(
    closure: *const z_owned_closure_reply_t,
) -> bool {
    guard_val(false, || !closure.is_null() && (*closure).call.is_some())
}

/// Borrow an owned reply closure (pico `z_closure_reply_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_reply_loan(
    closure: *const z_owned_closure_reply_t,
) -> *const z_loaned_closure_reply_t {
    closure as *const z_loaned_closure_reply_t
}

/// Move-cast an owned reply closure (pico `z_closure_reply_move`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_reply_move(
    closure: *mut z_owned_closure_reply_t,
) -> *mut z_moved_closure_reply_t {
    closure as *mut z_moved_closure_reply_t
}

/// Take an owned reply closure out of `src` into `dst` (pico
/// `z_closure_reply_take`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_reply_take(
    dst: *mut z_owned_closure_reply_t,
    src: *mut z_moved_closure_reply_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).context = (*src)._this.context;
    (*dst).call = (*src)._this.call;
    (*dst).drop = (*src)._this.drop;
    (*src)._this = z_owned_closure_reply_t::null_value();
}

/// Drop an owned reply closure that was never handed to a get (pico
/// `z_closure_reply_drop`): run the C `drop(context)` and null the struct.
#[no_mangle]
pub unsafe extern "C" fn z_closure_reply_drop(closure: *mut z_moved_closure_reply_t) {
    let _ = guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        let owned = &mut (*closure)._this;
        if let Some(dropfn) = owned.drop {
            dropfn(owned.context);
        }
        *owned = z_owned_closure_reply_t::null_value();
        Z_OK
    });
}

// --- get options -----------------------------------------------------------

/// Get options (pico `z_get_options_t`, `api/types.h:479-497`).
///
/// This is the DEFAULT-build layout. Two of pico's fields are compiled out and
/// so are absent here: `allowed_destination` exists only under
/// `Z_FEATURE_LOCAL_QUERYABLE` (default **0**, `~/zenoh-pico/CMakeLists.txt:353`)
/// and `source_info` / `cancellation_token` only under `Z_FEATURE_UNSTABLE_API`
/// (default **0**, `CMakeLists.txt:316`). Mirroring api.c's feature gates rather
/// than the header is the rule this crate follows: the header declares fields
/// unconditionally, the gates decide what a default build actually has.
#[repr(C)]
pub struct z_get_options_t {
    /// `z_moved_bytes_t*` — the query's value payload. Honoured.
    pub payload: *mut z_moved_bytes_t,
    /// `z_moved_encoding_t*`. Opaque: the encoding family is a follow-up round,
    /// so a C program linking this library has no exported `z_encoding_*` to
    /// build one with and this is always null in practice.
    pub encoding: *mut c_void,
    pub consolidation: z_query_consolidation_t,
    pub congestion_control: c_int,
    pub priority: c_int,
    pub is_express: bool,
    pub target: z_query_target_t,
    pub timeout_ms: u64,
    /// `z_moved_bytes_t*` — an optional attachment on the query. Honoured.
    pub attachment: *mut z_moved_bytes_t,
    pub accept_replies: z_reply_keyexpr_t,
}

/// Fill default get options (pico `z_get_options_default`,
/// `src/api/api.c:1723-1741`).
///
/// Note `accept_replies` defaults to `Z_REPLY_KEYEXPR_MATCHING_QUERY`, not ANY:
/// `z_reply_keyexpr_default()` is `Z_REPLY_KEYEXPR_DEFAULT` which is defined as
/// `Z_REPLY_KEYEXPR_MATCHING_QUERY` (`api/constants.h:291`). And `timeout_ms`
/// defaults to **0**, which `z_get` then rewrites to
/// [`Z_GET_TIMEOUT_DEFAULT`] — 0 here means "default", never "infinite".
#[no_mangle]
pub unsafe extern "C" fn z_get_options_default(options: *mut z_get_options_t) {
    if options.is_null() {
        return;
    }
    (*options).payload = std::ptr::null_mut();
    (*options).encoding = std::ptr::null_mut();
    (*options).consolidation = z_query_consolidation_t {
        mode: Z_CONSOLIDATION_MODE_AUTO,
    };
    // `z_internal_congestion_control_default_request()` = BLOCK
    // (`api/constants.h:224-226`) — NOT the DROP the push-side default uses.
    (*options).congestion_control = crate::query::Z_CONGESTION_CONTROL_BLOCK;
    (*options).priority = crate::query::Z_PRIORITY_DEFAULT;
    (*options).is_express = false;
    (*options).target = Z_QUERY_TARGET_BEST_MATCHING;
    (*options).timeout_ms = 0;
    (*options).attachment = std::ptr::null_mut();
    (*options).accept_replies = crate::query::Z_REPLY_KEYEXPR_MATCHING_QUERY;
}

// --- query-option constructors ---------------------------------------------
//
// pico's seven option constructors (`~/zenoh-pico/src/api/api.c:442-462`,
// declared `include/zenoh-pico/api/primitives.h:1021-1080`). All are UNGATED —
// they sit outside every `#if` in both files — so a default build has all seven
// and a drop-in must too.
//
// R311y296 exports them because they are the idiomatic way a pico program fills
// `z_get_options_t`: `opts.consolidation = z_query_consolidation_none();` is the
// documented form, and without these it fails to link. Six of the seven sit
// squarely in the basic `z_get` flow — far more mainstream than the querier
// family this round deliberately withholds — and this crate's own docs cite
// `z_reply_keyexpr_default()` and `z_query_consolidation_default()` as the
// authority for the defaults while not exporting them, which was incoherent.

/// pico `z_query_target_default` (`api.c:442`) — `Z_QUERY_TARGET_DEFAULT`.
#[no_mangle]
pub extern "C" fn z_query_target_default() -> z_query_target_t {
    Z_QUERY_TARGET_BEST_MATCHING
}

/// pico `z_reply_keyexpr_default` (`api.c:444`) — `Z_REPLY_KEYEXPR_DEFAULT`,
/// which is `Z_REPLY_KEYEXPR_MATCHING_QUERY` (`api/constants.h:291`), NOT ANY.
#[no_mangle]
pub extern "C" fn z_reply_keyexpr_default() -> z_reply_keyexpr_t {
    crate::query::Z_REPLY_KEYEXPR_MATCHING_QUERY
}

/// pico `z_query_consolidation_auto` (`api.c:446-448`).
#[no_mangle]
pub extern "C" fn z_query_consolidation_auto() -> z_query_consolidation_t {
    z_query_consolidation_t {
        mode: Z_CONSOLIDATION_MODE_AUTO,
    }
}

/// pico `z_query_consolidation_latest` (`api.c:450-462` family).
#[no_mangle]
pub extern "C" fn z_query_consolidation_latest() -> z_query_consolidation_t {
    z_query_consolidation_t {
        mode: Z_CONSOLIDATION_MODE_LATEST,
    }
}

/// pico `z_query_consolidation_monotonic`.
#[no_mangle]
pub extern "C" fn z_query_consolidation_monotonic() -> z_query_consolidation_t {
    z_query_consolidation_t {
        mode: Z_CONSOLIDATION_MODE_MONOTONIC,
    }
}

/// pico `z_query_consolidation_none`.
#[no_mangle]
pub extern "C" fn z_query_consolidation_none() -> z_query_consolidation_t {
    z_query_consolidation_t {
        mode: Z_CONSOLIDATION_MODE_NONE,
    }
}

/// pico `z_query_consolidation_default` (`api.c:462`) — an alias of
/// [`z_query_consolidation_auto`], not of `_none`.
#[no_mangle]
pub extern "C" fn z_query_consolidation_default() -> z_query_consolidation_t {
    z_query_consolidation_auto()
}

/// The effective timeout for a get, applying pico's `0 → default` rewrite
/// (`src/api/api.c:1762-1764`).
///
/// R311y326 — the 0->default rewrite here is now redundant with
/// `QueryOptions::effective_timeout_ms`, which resolves `0` to
/// `DEFAULT_QUERY_TIMEOUT_MS` on a `query-timeout` build (this crate composes
/// it). It is kept deliberately: this doc used to warn that wz's `timeout_ms = 0`
/// meant the OPPOSITE ("never expires"), which was true pre-y326 and remains true
/// on a hypothetical `query-timeout`-off build, so rewriting here keeps the C API
/// correct regardless of wz's feature set. The genuinely load-bearing half below
/// is the `u64 -> u32` saturation, which the wz accessor does not do.
///
/// wz's `QueryOptions::timeout_ms` is a `u32`; pico's is a `u64`. A value past
/// `u32::MAX` (~49 days) saturates rather than wrapping — wrapping could turn a
/// huge timeout into a tiny one and expire a get almost immediately, which is
/// the one failure mode worth spending a `min` on.
fn get_timeout_ms(timeout_ms: u64) -> u32 {
    let effective = if timeout_ms == 0 {
        Z_GET_TIMEOUT_DEFAULT
    } else {
        timeout_ms
    };
    effective.min(u32::MAX as u64) as u32
}

/// The wz query options one C `z_get_options_t` maps to.
///
/// `allowed_destination` is pinned [`Locality::Remote`], and that is load-bearing
/// rather than a default:
///
/// **Fidelity.** pico's `allowed_destination` field exists only under
/// `Z_FEATURE_LOCAL_QUERYABLE`, which defaults to **0**, and this crate's
/// queryables are declared `Locality::Remote` for the same reason
/// ([`crate::faces::queryable_options`]). A default pico build has no local
/// queryable for a get to reach, so Remote-only IS the faithful default.
///
/// **Soundness.** It closes the `allows_local` gate on `Session::query`'s
/// loopback fan and its drain (`session/mod.rs:1976, 2023`), which is what keeps
/// the C application thread out of `call`. See the `unsafe impl Sync for
/// CReplyClosure` above — this function is half of that proof.
fn get_options(
    target: z_query_target_t,
    consolidation: z_consolidation_mode_t,
    parameters: Vec<u8>,
    timeout_ms: u64,
    payload: Option<Vec<u8>>,
    attachment: Option<Vec<u8>>,
) -> QueryOptions {
    let mut opts = QueryOptions::get()
        .with_allowed_destination(Locality::Remote)
        .with_timeout_ms(get_timeout_ms(timeout_ms));

    // `Z_QUERY_TARGET_BEST_MATCHING` is deliberately NOT representable in wz's
    // `QueryTarget`: pico's encoder clears the target ext when the value is
    // BEST_MATCHING (`protocol/definitions/network.c:27`), so "no ext" IS how
    // BEST_MATCHING is transmitted and leaving `opts.target` unset reproduces
    // those bytes exactly. An unknown value takes the same path as pico's own
    // `!=` predicate would.
    match target {
        Z_QUERY_TARGET_ALL => opts = opts.with_target(QueryTarget::All),
        Z_QUERY_TARGET_ALL_COMPLETE => opts = opts.with_target(QueryTarget::AllComplete),
        _ => {}
    }

    // pico resolves AUTO on the CLIENT before encoding
    // (`src/net/primitives.c:567-573`): `_time=` in the selector → NONE (a
    // time-ranged query wants every matching sample), else LATEST. So AUTO never
    // reaches the wire, which is why wz's `ConsolidationMode` has no `Auto`
    // variant to map onto.
    //
    // R311y321 — the resolved mode is now HONOURED, not merely transmitted: the
    // `with_consolidation` call below sets the wire ext AND selects the
    // reception-side `ConsolidatingSink` mode, so AUTO -> LATEST here means a
    // default `z_get` consolidates per keyexpr exactly as pico's does. The
    // pre-y321 comment said the opposite ("it sets the wire ext and nothing
    // else"), which was true then and is retracted now. MONOTONIC is the one
    // mode that deliberately diverges from pico — see the module doc.
    let resolved = if consolidation == Z_CONSOLIDATION_MODE_AUTO {
        if parameters_has_time_selector(&parameters) {
            Z_CONSOLIDATION_MODE_NONE
        } else {
            Z_CONSOLIDATION_MODE_LATEST
        }
    } else {
        consolidation
    };
    match resolved {
        Z_CONSOLIDATION_MODE_NONE => opts = opts.with_consolidation(ConsolidationMode::None),
        Z_CONSOLIDATION_MODE_MONOTONIC => {
            opts = opts.with_consolidation(ConsolidationMode::Monotonic)
        }
        Z_CONSOLIDATION_MODE_LATEST => opts = opts.with_consolidation(ConsolidationMode::Latest),
        // Out of pico's enum (a caller writing a raw int). NAMED DIVERGENCE,
        // stated precisely because an earlier comment here got its own citation
        // backwards: pico's encode predicate is `_consolidation !=
        // Z_CONSOLIDATION_MODE_DEFAULT` (`codec/message.c:401`) and DEFAULT is
        // AUTO = -1 (`constants.h:184,188`), which `primitives.c:567-573` has
        // ALREADY resolved away by this point — so for a get the predicate can
        // never elide, and pico emits Q_C with the raw byte (e.g. 7). wz's
        // `ConsolidationMode` is a closed enum with no raw arm, so it emits no
        // Q_C at all. Garbage in, so not worth an upstream raw-byte escape
        // hatch; named rather than silently "conservative".
        _ => {}
    }

    if !parameters.is_empty() {
        opts = opts.with_parameters(parameters);
    }
    if let Some(payload) = payload {
        opts = opts.with_payload(payload);
    }
    if let Some(attachment) = attachment {
        opts = opts.with_attachment(attachment);
    }
    opts
}

/// pico's `Z_SELECTOR_TIME` = `"_time="` (`api/constants.h:17`) — the selector
/// key whose presence makes an AUTO consolidation resolve to NONE.
const SELECTOR_TIME: &[u8] = b"_time=";

/// Whether the selector parameters carry a `_time=` range, pico's
/// `_z_strstr(parameters, parameters + parameters_len, Z_SELECTOR_TIME) != NULL`
/// (`src/net/primitives.c:568`).
///
/// A plain substring search, deliberately: unlike `_anyke` (whose responder-side
/// parse enforces `;` boundaries), pico's AUTO resolution really is an
/// unanchored `_z_strstr`, so anchoring it here would DIVERGE — a selector such
/// as `xx_time=1` resolves to NONE in pico and must resolve to NONE here.
fn parameters_has_time_selector(parameters: &[u8]) -> bool {
    parameters
        .windows(SELECTOR_TIME.len())
        .any(|window| window == SELECTOR_TIME)
}

/// The selector parameters to transmit, applying pico's implicit-`_anyke`
/// append (`src/net/primitives.c:575-578` + `codec/message.c:413-425`).
///
/// `accept_replies == Z_REPLY_KEYEXPR_ANY` is not a wire field: pico transmits
/// it by APPENDING `_anyke` to the parameter list (with a `;` separator when the
/// list is non-empty), and the responder recovers it by parsing the list — which
/// is exactly what R3a's [`crate::query::parameters_has_anyke`] does on the
/// receive side. Reproducing the append here therefore makes wz's plain
/// `parameters` bytes byte-identical to pico's encoded ones, with no
/// `implicit_anyke` concept needed in the wz encoder.
///
/// The `!_anyke_in_parameters` guard is pico's own ("extra _anyke parameter only
/// if it's not already in the parameters list"), so a caller that wrote `_anyke`
/// by hand AND asked for ANY does not get it twice.
fn transmit_parameters(parameters: &[u8], accept_replies: z_reply_keyexpr_t) -> Vec<u8> {
    let mut out = parameters.to_vec();
    let anyke_option = accept_replies == crate::query::Z_REPLY_KEYEXPR_ANY;
    if anyke_option && !parameters_has_anyke(&out) {
        if !out.is_empty() {
            out.push(PARAM_SEPARATOR);
        }
        out.extend_from_slice(ANYKE_PARAM);
    }
    out
}

// --- z_get -----------------------------------------------------------------

/// Shared body of `z_get` / `z_get_with_parameters_substr`.
///
/// The moved closure and both moved byte arguments are consumed on EVERY path
/// (pico's contract — its own `z_get` takes the closure by value up front and
/// `z_bytes_drop`s payload/attachment at every exit, `src/api/api.c:1753-1786`).
///
/// # Safety
/// The pointers must be null or valid values of their types; `parameters` must
/// be null or readable for `parameters_len` bytes.
unsafe fn get_inner(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    parameters: *const std::ffi::c_char,
    parameters_len: usize,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_get_options_t,
) -> ZResult {
    // Consume the moved payload / attachment FIRST — before the null-callback
    // return below, which is a path they must also be freed on. `z_bytes_*` IS
    // exported, so a C program can build these; taking them only after the
    // callback check would leak both on `z_get(zs, ke, p, NULL, &opts)` and
    // leave the caller's `z_owned_bytes_t` non-null, so ownership would be
    // ambiguous rather than merely leaked. The sibling `z_put` takes its bytes
    // first for the same reason. There is no pico behaviour to mirror here
    // (pico derefs the null callback and crashes); the standard is this
    // function's own consume-on-EVERY-path contract.
    let (payload, attachment) = if options.is_null() {
        (None, None)
    } else {
        (
            crate::pubsub::take_moved_bytes((*options).payload),
            crate::pubsub::take_moved_bytes((*options).attachment),
        )
    };

    if callback.is_null() {
        return Z_ERR_NULL;
    }
    // Adopt the closure FIRST and null the source, exactly as pico does
    // (`_z_closure_reply_t closure = callback->_this._val;
    //   z_internal_closure_reply_null(&callback->_this);`). From here the
    // `CReplyClosure` owns the C `drop(context)`, so every early return below
    // frees it — and, because the drop IS the completion signal, an early error
    // also correctly reports "this get is over".
    let owned = &mut (*callback)._this;
    let cclosure = Arc::new(CReplyClosure::new(owned.context, owned.call, owned.drop));
    *owned = z_owned_closure_reply_t::null_value();

    let state = match session_state(zs) {
        Some(s) => s,
        None => return Z_ERR_NULL,
    };
    let ke = match keyexpr_str(keyexpr) {
        Some(k) => k.to_owned(),
        None => return Z_ERR_INVALID,
    };
    // Reject a non-canonical / pico-unsafe keyexpr up front — the gate the
    // declare paths hoist, for the same reason: the fan is best-effort per face,
    // so a per-face reject would be swallowed and the call would report Z_OK.
    if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
        return Z_ERR_INVALID;
    }

    // pico dereferences `options` only when non-null and otherwise fills the
    // defaults (`api.c:1756-1761`), so a null `options` is a valid default get.
    let (target, consolidation, timeout_ms, accept_replies) = if options.is_null() {
        (
            Z_QUERY_TARGET_BEST_MATCHING,
            Z_CONSOLIDATION_MODE_AUTO,
            0u64,
            crate::query::Z_REPLY_KEYEXPR_MATCHING_QUERY,
        )
    } else {
        (
            (*options).target,
            (*options).consolidation.mode,
            (*options).timeout_ms,
            (*options).accept_replies,
        )
    };

    let params_in: &[u8] = if parameters.is_null() || parameters_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(parameters as *const u8, parameters_len)
    };
    let params = transmit_parameters(params_in, accept_replies);

    // pico's `pen_qry->_anyke` is the OR of the option and the selector the
    // caller wrote by hand: `_anyke_in_parameters || _anyke_option`
    // (`~/zenoh-pico/src/net/primitives.c:575-582`). Read off `params` -- which
    // `transmit_parameters` has already normalised -- so the receive gate and
    // the transmitted bytes cannot disagree.
    let gate = Arc::new(ReplyGate {
        query_keyexpr: ke.clone(),
        anyke: parameters_has_anyke(&params),
    });

    let opts = get_options(
        target,
        consolidation,
        params,
        timeout_ms,
        payload,
        attachment,
    );

    fan_get(&state.shared.clone(), &ke, &opts, cclosure, gate)
}

/// Fan one C get across every connected face, returning `Z_OK`.
///
/// The C thread holds its own `Arc` clone (`guard`) for the whole loop. That is
/// load-bearing: without it, a face answering and dropping its pending entry
/// before the NEXT face's `query` is issued would take the refcount to zero and
/// run the C `drop(context)` — completing the get while it was still being
/// issued.
///
/// The sessions are snapshotted OUT of the registry lock before any `query`
/// runs (the `publish_all` pattern): a `query` can stage work whose drain fires
/// a C callback, and a pico callback is explicitly allowed to re-enter the
/// session (`z_put` from inside one is supported), so holding the lock across it
/// would deadlock the non-reentrant mutex.
///
/// Zero faces is `Z_OK` with no query issued: `guard` is then the last clone, so
/// the C `drop(context)` runs here on the C thread and the get completes
/// immediately with no reply. That is pico's own behaviour for an empty peer set
/// — `_z_query` runs `_z_drop_handler_execute(dropper, arg)` on the caller
/// thread when `remaining_finals == 0` (`src/net/primitives.c:560-562`).
fn fan_get(
    shared: &Arc<SharedSession>,
    keyexpr: &str,
    opts: &QueryOptions,
    closure: Arc<CReplyClosure>,
    gate: Arc<ReplyGate>,
) -> ZResult {
    let guard = closure.clone();
    for (session, revised) in shared.face_sessions_with_wake() {
        let per_face = closure.clone();
        let per_face_gate = gate.clone();
        // Only `on_reply` carries the `Arc`. `on_final` needs no body at all:
        // completion is signalled by the pending entry's sink being DROPPED
        // (which drops this closure and releases the clone), and that happens on
        // a real final, a timeout sweep, and a face death alike — whereas a
        // counter incremented here would never be reached by the face-death
        // path. See the module doc.
        let issued = session.query(
            keyexpr,
            opts.clone(),
            move |view: &dyn ReplyView| fire_reply(&per_face, &per_face_gate, view),
            |_rid| {},
        );
        // A per-face issue error (a face mid-teardown) is swallowed, matching
        // the fan-out publish's best-effort discipline. Its `Arc` clone was
        // already dropped with the rolled-back sink, so it cannot hold the get
        // open — and if EVERY face errors, `guard` below completes it.
        drop(issued);
        // Wake this face's drive loop so it re-arms on the deadline just
        // registered. Without this the loop stays parked on whatever it armed
        // BEFORE the get existed — in a silent session that is the keepalive
        // wake, ~3333 ms out, so every get would be swept that late however
        // short its timeout. `notify_one` (not `notify_waiters`) because the
        // loop is not necessarily parked in that arm right now: the permit is
        // stored and honoured at its next arm instead of being dropped.
        //
        // Issued even when `query` errored: the wake is idempotent and a
        // spurious one only costs a recompute, whereas reasoning about which
        // failure modes still need it would be a standing invariant to get
        // wrong.
        revised.notify_one();
    }
    drop(guard);
    Z_OK
}

/// Send a distributed query (pico `z_get`). Consumes the moved closure and the
/// moved `options->payload` / `options->attachment`.
///
/// `parameters` is a NUL-terminated C string; pico's own `z_get` is exactly this
/// `strlen` delegation to [`z_get_with_parameters_substr`]
/// (`src/api/api.c:1743-1746`).
///
/// Of `options`: `payload`, `attachment`, `target`, `timeout_ms` and
/// `accept_replies` are honoured — the last on BOTH halves (the `_anyke`
/// selector append and the receive-side [`ReplyGate`]).
///
/// `consolidation` is TRANSMITTED but not applied: see `THE CONSOLIDATION
/// DIVERGENCE` in the module doc. `encoding` is unreachable (opaque, no exported
/// constructor). `congestion_control` / `priority` / `is_express` are carried for
/// layout and dropped — a NAMED DIVERGENCE: they map to a `_z_n_qos_t` on pico's
/// Request (`api.c:1773`), and wz's `QueryOptions` has no QoS arm to route them
/// to. They affect scheduling and batching, not delivery or content.
#[no_mangle]
pub unsafe extern "C" fn z_get(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    parameters: *const std::ffi::c_char,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_get_options_t,
) -> ZResult {
    guarded(|| {
        let len = if parameters.is_null() {
            0
        } else {
            std::ffi::CStr::from_ptr(parameters).to_bytes().len()
        };
        get_inner(zs, keyexpr, parameters, len, callback, options)
    })
}

/// Send a distributed query with explicitly-sized parameters (pico
/// `z_get_with_parameters_substr`) — the variant for a selector that is a
/// SUBSTRING of a larger buffer and so not NUL-terminated at its end.
#[no_mangle]
pub unsafe extern "C" fn z_get_with_parameters_substr(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    parameters: *const std::ffi::c_char,
    parameters_len: usize,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_get_options_t,
) -> ZResult {
    guarded(|| get_inner(zs, keyexpr, parameters, parameters_len, callback, options))
}

// --- loaned-reply accessors ------------------------------------------------

/// Whether the reply is a data reply rather than an error (pico
/// `z_reply_is_ok`). A null / spent reply reports `false`, the conservative
/// answer (pico would dereference and crash).
#[no_mangle]
pub unsafe extern "C" fn z_reply_is_ok(reply: *const z_loaned_reply_t) -> bool {
    guard_val(false, || {
        reply_marshal(reply).is_some_and(|marshal| marshal.is_ok)
    })
}

/// Borrow a data reply's sample (pico `z_reply_ok`). The C side must check
/// [`z_reply_is_ok`] first — pico documents the same precondition; here a
/// mismatched call yields null rather than a garbage sample.
///
/// Read the sample's Put/Del discriminant with `z_sample_kind`: R3a's
/// `z_query_reply_del` can produce a Del reply, whose payload is legitimately
/// empty.
#[no_mangle]
pub unsafe extern "C" fn z_reply_ok(reply: *const z_loaned_reply_t) -> *const z_loaned_sample_t {
    guard_val(std::ptr::null(), || match reply_marshal(reply) {
        Some(marshal) if marshal.is_ok => marshal.sample.as_loaned(),
        _ => std::ptr::null(),
    })
}

/// Borrow an error reply's error (pico `z_reply_err`). Null unless the reply is
/// an Err — the mirror of [`z_reply_ok`]'s gate.
#[no_mangle]
pub unsafe extern "C" fn z_reply_err(
    reply: *const z_loaned_reply_t,
) -> *const z_loaned_reply_err_t {
    guard_val(std::ptr::null(), || match reply_marshal(reply) {
        Some(marshal) if !marshal.is_ok => {
            marshal as *const ReplyMarshal as *const z_loaned_reply_err_t
        }
        _ => std::ptr::null(),
    })
}

/// Borrow an error reply's payload — the error blob (pico
/// `z_reply_err_payload`).
#[no_mangle]
pub unsafe extern "C" fn z_reply_err_payload(
    reply_err: *const z_loaned_reply_err_t,
) -> *const z_loaned_bytes_t {
    guard_val(std::ptr::null(), || match reply_err_marshal(reply_err) {
        Some(marshal) => &marshal.loaned_err_payload as *const z_loaned_bytes_t,
        None => std::ptr::null(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pico rewrites `timeout_ms == 0` to `Z_GET_TIMEOUT_DEFAULT` before
    /// issuing (`api.c:1762-1764`); [`get_timeout_ms`] mirrors that so C's 0
    /// becomes the 10s default. R311y326 — the rewrite is now belt-and-suspenders
    /// on a `query-timeout` build (this crate composes it): wz's
    /// `QueryOptions::effective_timeout_ms` ALSO resolves a 0 to the default, so
    /// C's 0 would reach 10s either way. The rewrite is kept for the `u64 -> u32`
    /// saturation and to stay correct on a hypothetical `query-timeout`-off
    /// build, where wz's 0 still means never-expire. The test name predates
    /// y326; what it pins is `get_timeout_ms(0) == 10_000`, which is unchanged.
    #[test]
    fn timeout_zero_means_picos_default_not_wzs_never_expires() {
        assert_eq!(
            get_timeout_ms(0),
            10_000,
            "0 is pico's DEFAULT sentinel, not 'no timeout'"
        );
        assert_eq!(get_timeout_ms(1), 1, "a real timeout passes through");
        assert_eq!(get_timeout_ms(100), 100);
        // pico's field is u64, wz's is u32: saturate rather than wrap. Wrapping
        // would turn a huge timeout into a tiny one and expire the get almost
        // at once — the one failure mode worth guarding.
        assert_eq!(get_timeout_ms(u64::MAX), u32::MAX);
        assert_eq!(get_timeout_ms(u32::MAX as u64 + 1), u32::MAX);
    }

    /// `accept_replies = ANY` is transmitted by APPENDING `_anyke` to the
    /// selector, which is precisely what R3a's responder-side parse recovers.
    /// This is the querier half of that round-trip.
    #[test]
    fn accept_replies_any_appends_picos_implicit_anyke() {
        let any = crate::query::Z_REPLY_KEYEXPR_ANY;
        let matching = crate::query::Z_REPLY_KEYEXPR_MATCHING_QUERY;

        // Empty selector → the bare key (pico's no-params encoder arm).
        assert_eq!(transmit_parameters(b"", any), b"_anyke".to_vec());
        // Non-empty → `;`-separated (pico's has_params arm).
        assert_eq!(transmit_parameters(b"a=1", any), b"a=1;_anyke".to_vec());
        // MATCHING_QUERY (the DEFAULT) appends nothing.
        assert_eq!(transmit_parameters(b"a=1", matching), b"a=1".to_vec());
        assert_eq!(transmit_parameters(b"", matching), b"".to_vec());
        // pico's own guard: don't append when the caller already wrote it.
        assert_eq!(transmit_parameters(b"_anyke", any), b"_anyke".to_vec());
        assert_eq!(
            transmit_parameters(b"a=1;_anyke", any),
            b"a=1;_anyke".to_vec()
        );
        // ...but a DECOY is not the flag, so the append still happens (the
        // boundary rules R3a ported are what make this the right answer).
        assert_eq!(
            transmit_parameters(b"no_anyke", any),
            b"no_anyke;_anyke".to_vec()
        );
    }

    /// The querier-side round-trip that pins R3a against R3b: what
    /// `transmit_parameters` emits is what `parameters_has_anyke` reads back.
    #[test]
    fn transmitted_anyke_is_recovered_by_the_responder_parse() {
        for selector in [&b""[..], b"a=1", b"a=1;b=2", b"no_anyke", b"_anykey=1"] {
            let sent = transmit_parameters(selector, crate::query::Z_REPLY_KEYEXPR_ANY);
            assert!(
                parameters_has_anyke(&sent),
                "an ANY get's selector {sent:?} must parse as _anyke on the responder"
            );
            let sent = transmit_parameters(selector, crate::query::Z_REPLY_KEYEXPR_MATCHING_QUERY);
            assert!(
                !parameters_has_anyke(&sent),
                "a MATCHING_QUERY get's selector {sent:?} must NOT parse as _anyke"
            );
        }
    }

    /// The RECEIVE half of `accept_replies`: a reply the query does not accept
    /// is dropped before the C callback ever sees it, pico's
    /// `!_anyke && !_z_keyexpr_intersects` (`~/zenoh-pico/src/session/query.c:121`).
    ///
    /// It is an INTERSECTION, so a wildcard get admits concrete replies — the
    /// ordinary case, not an edge one. Shares the responder side's SSOT, so this
    /// also pins the two halves against drifting apart.
    #[test]
    fn the_reply_gate_drops_what_the_query_does_not_accept() {
        let matching = crate::query::Z_REPLY_KEYEXPR_MATCHING_QUERY;
        let any = crate::query::Z_REPLY_KEYEXPR_ANY;

        // The default is MATCHING_QUERY, so the gate is ON by default.
        let gate = |ke: &str, accept| ReplyGate {
            query_keyexpr: ke.to_owned(),
            anyke: parameters_has_anyke(&transmit_parameters(b"", accept)),
        };

        let g = gate("a/**", matching);
        assert!(
            !g.anyke,
            "MATCHING_QUERY is the default and leaves anyke off"
        );
        assert!(crate::query::reply_keyexpr_is_covered(
            &g.query_keyexpr,
            "a/b",
            g.anyke
        ));
        assert!(
            !crate::query::reply_keyexpr_is_covered(&g.query_keyexpr, "z/b", g.anyke),
            "a reply on a disjoint key must be dropped — pico's query.c:121"
        );

        // ANY switches the gate off wholesale, on both halves at once.
        let g = gate("a/**", any);
        assert!(
            g.anyke,
            "Z_REPLY_KEYEXPR_ANY must reach the receive gate too"
        );
        assert!(crate::query::reply_keyexpr_is_covered(
            &g.query_keyexpr,
            "z/b",
            g.anyke
        ));

        // pico ORs the option with a hand-written selector
        // (`primitives.c:575-582`), so `_anyke` in the caller's own parameters
        // opens the gate even under MATCHING_QUERY.
        let g = ReplyGate {
            query_keyexpr: "a/**".to_owned(),
            anyke: parameters_has_anyke(&transmit_parameters(b"_anyke", matching)),
        };
        assert!(g.anyke, "a hand-written _anyke selector must open the gate");
    }

    /// pico resolves AUTO on the client: `_time=` in the selector → NONE, else
    /// LATEST (`src/net/primitives.c:567-573`). The search is an unanchored
    /// `_z_strstr`, so — unlike `_anyke` — a decoy DOES match, and reproducing
    /// that is fidelity, not a bug.
    #[test]
    fn auto_consolidation_resolves_on_the_time_selector_like_pico() {
        assert!(parameters_has_time_selector(b"_time=[now(-1h)..now()]"));
        assert!(parameters_has_time_selector(b"a=1;_time=[..]"));
        assert!(!parameters_has_time_selector(b""));
        assert!(!parameters_has_time_selector(b"a=1"));
        // `_z_strstr` is unanchored: pico matches these too, so we must.
        assert!(parameters_has_time_selector(b"xx_time=1"));
        // ...but a `_time` without the `=` is not the key.
        assert!(!parameters_has_time_selector(b"_time"));
    }
}

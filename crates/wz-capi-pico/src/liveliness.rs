// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_liveliness_*` — the presence plane: declare a token, subscribe to tokens.
//!
//! Both halves bind to wz atoms that already exist and are ACTIVE
//! (`liveliness-token`, `liveliness-subscriber`), so nothing here is new
//! protocol; it is the C-side binding plus the per-face fan-out this crate
//! applies to every declaration.
//!
//! ## Both halves are SSOTs, for the same reason every declaration here is
//!
//! A C session is N per-face wz sessions, so a token declared before a peer
//! connects must still reach that peer, and a token declared while three peers
//! are connected must reach all three. The registry therefore records both a
//! token entry and a liveliness-subscription entry and replays them in
//! `face_up`, exactly as it does for subscriptions, queryables and keyexpr
//! aliases. Without that, a token would be visible only to whichever peers
//! happened to be connected at declare time — which for upstream's own
//! `z_liveliness.c` (declare, then sleep) is frequently none of them.
//!
//! ## Dropping a token UNDECLARES it, and that is not incidental
//!
//! pico's `z_liveliness_token_drop` runs `_z_liveliness_token_clear`, which
//! calls `_z_undeclare_liveliness_token`
//! (`vendor/zenoh-pico/src/api/liveliness.c:35-43`) — so a token going out of
//! scope is what tells subscribers the resource is gone. Upstream's
//! `z_liveliness.c` relies on it: it never calls
//! `z_liveliness_undeclare_token`, it just drops. A drop that only freed
//! memory would leave every subscriber believing the token is still alive,
//! which is the exact failure the plane exists to prevent.

use core::ffi::c_void;
use wz_capi_port::lodge::Strong;

#[cfg(feature = "liveliness-get")]
use wz_capi_port::cancellation::CancellationToken;
use wz_capi_port::TokenId;
#[cfg(feature = "liveliness-get")]
use wz_capi_port::WireKey;
use wz_session_core::declare::liveliness_sample::LivelinessSampleKind;

use crate::abi::z_loaned_keyexpr_t;
use crate::ffi::{guard_val, guarded};
use crate::keyexpr::{declared_of, outbound_keyexpr, DeclaredKeyexpr, EntityKey};
// The engine's operations, which a build of the cooperative engine reaches as its own type; a
// build that reaches it as the port's object calls them on that object.
#[cfg(not(feature = "engine-tokio"))]
use crate::prelude::*;
use crate::pubsub::{
    fill_subscriber_place, liveliness_sink, settle_subscriber, z_moved_closure_sample_t,
    z_owned_closure_sample_t, z_owned_subscriber_t, CClosure, DeclaredSubscriber, SubscriberState,
    Z_SAMPLE_KIND_DELETE, Z_SAMPLE_KIND_PUT,
};
use crate::refusal::{refusal_code, Door};
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};
use crate::session::{engine_held, z_loaned_session_t, EngineHold};
use crate::write_filter::PicoSession;

/// pico `z_liveliness_token_options_t` — a single `uint8_t __dummy`
/// (`api/liveliness.h:45-47`), 1 B measured. Carried for layout only; pico's
/// own default just zeroes it.
#[repr(C)]
pub struct z_liveliness_token_options_t {
    pub __dummy: u8,
}

/// pico `z_liveliness_subscriber_options_t` — `{ bool history }`
/// (`api/liveliness.h:89-91`), 1 B measured. `history` requests the peer's
/// CURRENT-state replay at declare time, which wz carries as the `history` argument of the
/// port's `declare_liveliness_subscriber_on_wire`.
#[repr(C)]
pub struct z_liveliness_subscriber_options_t {
    pub history: bool,
}

/// Owned liveliness token (pico `z_owned_liveliness_token_t`, 24 B measured).
/// Handle in slot 0, zero-padded to pico's size — the same model every other
/// owned handle type in [`crate::abi`] uses.
#[repr(C)]
pub struct z_owned_liveliness_token_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 2],
}

/// Loaned liveliness token (pico `z_loaned_liveliness_token_t`), same layout.
#[repr(C)]
pub struct z_loaned_liveliness_token_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 2],
}

/// Moved owned token (pico `z_moved_liveliness_token_t`).
#[repr(C)]
pub struct z_moved_liveliness_token_t {
    pub(crate) _this: z_owned_liveliness_token_t,
}

impl z_owned_liveliness_token_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            _pad: [core::ptr::null_mut(); 2],
        }
    }
}

/// Behind a `z_owned_liveliness_token_t` handle: the registry entry to retract.
///
/// Dropping this UNDECLARES on every face, which is what makes
/// [`z_liveliness_token_drop`] notify subscribers (pico's contract, above). The
/// retraction lives in `Drop` rather than in the export so that both the
/// explicit `z_liveliness_undeclare_token` and the implicit `z_drop` take the
/// identical path — the two must not be able to diverge.
///
/// The session's record of the token holds the whole-key declaration pico makes for it until the
/// token is retracted, so its retraction follows the token's; the door keeps no copy of the key.
pub(crate) struct TokenState {
    shared: EngineHold,
    id: TokenId,
}

impl TokenState {
    /// Declare a token on `keyexpr`: the whole key's declaration, then the token
    /// announced on it and retracted naming the key.
    ///
    /// R2959 — pico declares the whole key, announces the token on that
    /// declaration, and names it again in the retraction
    /// (`vendor/zenoh-pico/src/net/liveliness.c` @
    /// `_Z_RETURN_IF_ERR(_z_declared_keyexpr_declare(zn, &ke, keyexpr));` and
    /// `_z_declaration_t declaration = _z_make_undecl_token(id, &wireexpr);`).
    ///
    /// `existing` is the caller's own key when it is already a declaration,
    /// which is shared rather than declared again.
    pub(crate) fn declare(
        session: &PicoSession,
        keyexpr: &str,
        existing: Option<&DeclaredKeyexpr>,
    ) -> Result<Self, ZResult> {
        let key = EntityKey::whole(&session.engine, keyexpr, existing)?;
        let id = session
            .engine
            .declare_liveliness_token_on_wire(keyexpr, key.wire(), Some(key.retraction_key()))
            .map_err(|refused| refusal_code(refused, Door::Token))?;
        // The session's record holds the declaration from here on: the door's hold goes.
        drop(key);
        Ok(Self {
            shared: session.engine.clone(),
            id,
        })
    }
}

impl Drop for TokenState {
    fn drop(&mut self) {
        self.shared.undeclare_liveliness_token(self.id);
    }
}

/// Default token options (pico `z_liveliness_token_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_options_default(
    options: *mut z_liveliness_token_options_t,
) -> ZResult {
    guarded(|| {
        if options.is_null() {
            return Z_ERR_NULL;
        }
        (*options).__dummy = 0;
        Z_OK
    })
}

/// Default liveliness-subscriber options (pico
/// `z_liveliness_subscriber_options_default`). `history = false` — future
/// events only, which is pico's default and wz's.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_subscriber_options_default(
    options: *mut z_liveliness_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if options.is_null() {
            return Z_ERR_NULL;
        }
        (*options).history = false;
        Z_OK
    })
}

/// Declare a liveliness token (pico `z_liveliness_declare_token`).
///
/// Subscribers on an intersecting keyexpr see a PUT when the token appears and
/// a DELETE when it goes away; the DELETE half is [`z_liveliness_token_drop`].
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_declare_token(
    zs: *const z_loaned_session_t,
    token: *mut z_owned_liveliness_token_t,
    keyexpr: *const z_loaned_keyexpr_t,
    _options: *const z_liveliness_token_options_t,
) -> ZResult {
    guarded(|| {
        if token.is_null() {
            return Z_ERR_NULL;
        }
        // A closed session takes no declaration.
        let handle = match crate::session::open_session_handle(zs) {
            Ok(handle) => handle,
            Err(code) => return code,
        };
        // The gate every declaration takes: a key not in canon form is `Z_EINVAL`.
        let ke = match outbound_keyexpr(keyexpr) {
            Ok(key) => key,
            Err(code) => return code,
        };
        // The token's place is taken from its session before it is declared, so a session with
        // no place left refuses the declaration and declares nothing.
        let Some(slot) = crate::object_slot::Slot::take_entity(
            engine_held(handle),
            crate::object_slot::Kind::LivelinessToken,
        ) else {
            return crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        let state = match TokenState::declare(PicoSession::of(handle), ke, declared_of(keyexpr)) {
            Ok(token) => slot.fill(token),
            Err(rc) => return rc,
        };
        *token = z_owned_liveliness_token_t {
            handle: state as *mut c_void,
            _pad: [core::ptr::null_mut(); 2],
        };
        Z_OK
    })
}

/// Retract a liveliness token, notifying subscribers (pico
/// `z_liveliness_undeclare_token`). Consumes the moved value.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_undeclare_token(
    token: *mut z_moved_liveliness_token_t,
) -> ZResult {
    guarded(|| {
        if token.is_null() {
            return Z_OK;
        }
        let handle = (*token)._this.handle;
        if !handle.is_null() {
            // The retraction is `TokenState::drop`, so this is the same path
            // `z_liveliness_token_drop` takes — deliberately, so an explicit
            // undeclare and an implicit one cannot drift apart.
            crate::object_slot::release_entity(handle as *mut TokenState);
            (*token)._this = z_owned_liveliness_token_t::null_value();
        }
        Z_OK
    })
}

/// Zero an owned token in place (pico `z_internal_liveliness_token_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_liveliness_token_null(obj: *mut z_owned_liveliness_token_t) {
    if !obj.is_null() {
        *obj = z_owned_liveliness_token_t::null_value();
    }
}

/// `true` iff the owned token holds a live declaration (pico
/// `z_internal_liveliness_token_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_liveliness_token_check(
    obj: *const z_owned_liveliness_token_t,
) -> bool {
    guard_val(false, || !obj.is_null() && !(*obj).handle.is_null())
}

/// Borrow a token (pico `z_liveliness_token_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_loan(
    obj: *const z_owned_liveliness_token_t,
) -> *const z_loaned_liveliness_token_t {
    obj as *const z_loaned_liveliness_token_t
}

/// Borrow a token mutably (pico `z_liveliness_token_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_loan_mut(
    obj: *mut z_owned_liveliness_token_t,
) -> *mut z_loaned_liveliness_token_t {
    obj as *mut z_loaned_liveliness_token_t
}

/// Move-cast (pico `z_liveliness_token_move`).
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_move(
    obj: *mut z_owned_liveliness_token_t,
) -> *mut z_moved_liveliness_token_t {
    obj as *mut z_moved_liveliness_token_t
}

/// Take the value out of `src` into `dst` (pico `z_liveliness_token_take`).
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_take(
    dst: *mut z_owned_liveliness_token_t,
    src: *mut z_moved_liveliness_token_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = (*src)._this._pad;
    (*src)._this = z_owned_liveliness_token_t::null_value();
}

/// Drop a liveliness token (pico `z_liveliness_token_drop`).
///
/// This UNDECLARES — see the module docs. Upstream's `z_liveliness.c` never
/// calls the explicit undeclare, so a drop that only freed memory would leave
/// every subscriber believing the token is still alive.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_drop(obj: *mut z_moved_liveliness_token_t) {
    let _ = z_liveliness_undeclare_token(obj);
}

/// Declare a subscriber on liveliness tokens intersecting `keyexpr` (pico
/// `z_liveliness_declare_subscriber`). Consumes the moved closure.
///
/// The callback receives an ordinary `z_loaned_sample_t`, as pico's does: a
/// token appearing is a PUT and one going away is a DELETE, both with an EMPTY
/// payload. That mapping is not this crate's invention — wz's own
/// [`LivelinessSampleKind`] documents the same Put/Delete correspondence, and
/// upstream's `z_sub_liveliness.c` switches on `z_sample_kind` to print
/// "Alive"/"Dropped".
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_declare_subscriber(
    zs: *const z_loaned_session_t,
    sub: *mut z_owned_subscriber_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut z_liveliness_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if sub.is_null() || callback.is_null() {
            return Z_ERR_NULL;
        }
        match declare_liveliness_subscriber_with(zs, keyexpr, callback, options, false) {
            Ok(state) => {
                *sub = z_owned_subscriber_t {
                    handle: state as *mut c_void,
                    _pad: [core::ptr::null_mut(); 3],
                };
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// The body both liveliness subscriber doors of a session share: the moved closure taken (pico's
/// consume-on-all-paths contract, so every refusal below runs its C `drop(context)`), the session
/// and the key read, the subscriber's place taken from its session before anything is declared,
/// so a session with no place left declares nothing, and the subscriber declared there
/// ([`declare_liveliness_subscriber_in`]). A `background` subscriber takes its place as an owned
/// one does, and its closure holds its session's count open until it is let go of, which the
/// session's close waits on.
///
/// # Safety
/// `zs` and `keyexpr` null or live loans; `callback` a non-null valid moved closure; `options`
/// null or valid.
unsafe fn declare_liveliness_subscriber_with(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *const z_liveliness_subscriber_options_t,
    background: bool,
) -> Result<*mut SubscriberState, ZResult> {
    let owned = &mut (*callback)._this;
    let closure = CClosure::uncounted(owned.context, owned.call, owned.drop);
    *owned = z_owned_closure_sample_t::null_value();

    // A closed session takes no declaration; the closure consumed above runs its drop.
    let handle = crate::session::open_session_handle(zs)?;
    let ke = outbound_keyexpr(keyexpr)?;
    // A NULL options pointer is pico's "defaults", not an error.
    let history = !options.is_null() && (*options).history;
    let engine = engine_held(handle);
    let slot = crate::object_slot::Slot::<SubscriberState>::take_entity(
        engine,
        crate::object_slot::Kind::LivelinessSubscriber,
    )
    .ok_or(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)?;
    let session = background.then(|| crate::session::session_let_go(zs));
    declare_liveliness_subscriber_in(
        engine,
        slot,
        ke,
        declared_of(keyexpr),
        closure,
        history,
        session,
    )
}

/// Declare a liveliness subscriber of `engine` on `keyexpr` in its place, `slot`, its row
/// holding `closure`, with `session`, the hold a background subscriber's session's close waits
/// on, let go of after the closure. Answers the subscriber's state, declared, which its owner lets go of; a refused
/// declaration lets go of the row's callback, which drops the closure, and of the place.
///
/// R2959 — pico declares the WHOLE key for a liveliness subscriber and sends its interest on that
/// declaration (`vendor/zenoh-pico/src/net/liveliness.c` @
/// `_Z_CLEAN_RETURN_IF_ERR(_z_declared_keyexpr_declare(zn, &s._key, keyexpr), _z_subscription_clear(&s));`
/// and the `_z_make_interest(&wireexpr, ...)` on `sp_s->_key` below it); the key it is announced
/// on holds that declaration for as long as the engine's entry stands.
///
/// # Safety
/// `existing` is the caller's own key when it is already a declaration; `closure` is counted in
/// no owner (`CClosure::uncounted`).
pub(crate) unsafe fn declare_liveliness_subscriber_in(
    engine: &EngineHold,
    slot: crate::object_slot::Slot<SubscriberState>,
    keyexpr: &str,
    existing: Option<&DeclaredKeyexpr>,
    closure: CClosure,
    history: bool,
    session: Option<wz_capi_port::LetGo>,
) -> Result<*mut SubscriberState, ZResult> {
    // The row holds the closure; a refusal drops the sink, which lets the closure go, and the
    // session's hold after it.
    let sink = liveliness_sink(closure, session);
    let state = fill_subscriber_place(slot, engine);
    let declared = EntityKey::whole(engine, keyexpr, existing).and_then(|key| {
        engine
            .declare_liveliness_subscriber_on_wire(keyexpr, key.wire(), history, sink)
            // The session's record holds the declaration the key is announced on from here on:
            // the door's hold goes with `key`, and the key is lent from the record.
            .map(DeclaredSubscriber::new)
            .map_err(|refused| refusal_code(refused, Door::Entity))
    });
    settle_subscriber(state, declared)
}

// --- liveliness GET ---------------------------------------------------------

/// pico `z_liveliness_get_options_t` (`api/liveliness.h:142-147`), **16 B
/// measured** against the reference build's own headers.
///
/// R311y575 — this struct was 8 B, on the reasoning that the
/// `cancellation_token` field "exists only under `Z_FEATURE_UNSTABLE_API`,
/// which defaults OFF". That is the R311y466 trap the sibling
/// `z_get_options_t` doc names, and R311y562 had already paid for it once on
/// that struct: `scripts/build-zenoh-pico-cli.sh` configures the reference pico
/// with `-DZ_FEATURE_UNSTABLE_API=ON`, and
/// `target/zenoh-pico-build/zenohpico/include/zenoh-pico/config.h:35` carries a
/// bare `#define Z_FEATURE_UNSTABLE_API`. MEASURED against those headers the
/// struct is 16 B with `cancellation_token` at offset 8, so
/// `z_liveliness_get_options_default` was writing 8 of the 16 bytes a drop-in
/// program allocates and leaving the tail as whatever was on the caller's stack
/// — where upstream writes NULL (`src/api/liveliness.c:111-115`).
///
/// The defect survived R311y565's mechanical layout gate because that gate pins
/// the structs its `PINNED` table names and this type was not in it. Adding it
/// there is the half of this fix that keeps the next one from happening.
#[cfg(feature = "liveliness-get")]
#[repr(C)]
pub struct z_liveliness_get_options_t {
    /// Snapshot timeout in milliseconds. `0` means "use the default", NOT
    /// "never expire" — pico rewrites it before issuing
    /// (`src/api/liveliness.c:132-133`), and so does this crate.
    pub timeout_ms: u64,
    /// `z_moved_cancellation_token_t*` — HONOURED as of R311y575. Cancelling the
    /// token drops this snapshot get's pending registration; an ALREADY-cancelled
    /// token fails the call with `Z_ERR_CANCELLED` and sends no Interest, which
    /// is upstream's own ordering (`src/net/liveliness.c:284-310, 341`). Only with
    /// `unstable-api`, as only with `Z_FEATURE_UNSTABLE_API` upstream.
    #[cfg(feature = "unstable-api")]
    pub cancellation_token: *mut crate::cancellation::z_moved_cancellation_token_t,
}

#[cfg(feature = "liveliness-get")]
impl z_liveliness_get_options_t {
    /// The token the caller handed over, taken, as [`crate::get::z_get_options_t`]'s.
    ///
    /// # Safety
    /// The field must be null or a moved token this crate produced.
    #[cfg(feature = "unstable-api")]
    unsafe fn take_cancellation_token(&self) -> Option<Strong<CancellationToken>> {
        crate::cancellation::take_moved_cancellation_token(self.cancellation_token)
    }

    #[cfg(not(feature = "unstable-api"))]
    unsafe fn take_cancellation_token(&self) -> Option<Strong<CancellationToken>> {
        None
    }
}

/// The upstream layout this struct must match, measured against the reference
/// build's header. Pinned by OFFSET as well as size for the R311y562 reason: a
/// wrong size can mean a harmless missing tail or a displaced field, and only an
/// offset tells those apart. The mechanical gate
/// (`crates/wz-integration-tests/tests/pico_abi_option_layout.rs`) is what
/// notices upstream MOVING the field; this const is the compile-time floor under
/// it. Without the unstable API the struct is the 8 B timeout alone.
///
/// The offset holds on every host: the token follows an eight-byte `uint64_t`. The size and the
/// alignment are the 64-bit host's; on a 32-bit one they follow that ABI's alignment of a
/// `uint64_t` (4 on 32-bit x86 Linux, which makes the struct 12 B; 8 on Windows and ARM, 16 B),
/// which the `repr(C)` mirror of the same two fields takes from the target.
#[cfg(all(feature = "liveliness-get", feature = "unstable-api"))]
const _: () = {
    assert!(core::mem::offset_of!(z_liveliness_get_options_t, cancellation_token) == 8);
};

#[cfg(all(
    feature = "liveliness-get",
    feature = "unstable-api",
    target_pointer_width = "64"
))]
const _: () = {
    assert!(core::mem::size_of::<z_liveliness_get_options_t>() == 16);
    assert!(core::mem::align_of::<z_liveliness_get_options_t>() == 8);
};

#[cfg(all(feature = "liveliness-get", not(feature = "unstable-api")))]
const _: () = assert!(core::mem::size_of::<z_liveliness_get_options_t>() == 8);

/// Fill default liveliness-get options (pico `z_liveliness_get_options_default`,
/// `src/api/liveliness.c:111`).
#[cfg(feature = "liveliness-get")]
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_get_options_default(
    options: *mut z_liveliness_get_options_t,
) -> ZResult {
    guarded(|| {
        if options.is_null() {
            return Z_ERR_NULL;
        }
        (*options).timeout_ms = 0;
        // R311y575 — upstream writes this too (`src/api/liveliness.c:114`), and
        // not writing it was the OBSERVABLE half of the 8-vs-16 byte defect: a
        // caller's 16-byte struct kept whatever its stack held in the tail, so
        // the very next thing a drop-in program does with these options differs
        // from upstream on uninitialised memory.
        #[cfg(feature = "unstable-api")]
        {
            (*options).cancellation_token = core::ptr::null_mut();
        }
        Z_OK
    })
}

/// Query the liveliness tokens currently alive under `keyexpr` (pico
/// `z_liveliness_get`).
///
/// The wire here is the DECLARATION plane, not the query plane: the request is
/// a CURRENT liveliness `Interest`, each live token comes back as a
/// `Declare(DeclToken)` and the snapshot ends with one `DeclFinal`. wz models
/// that through the engine's `liveliness_get_on_wire`, whose application surface is
/// already reply-shaped — which is why this maps onto the same
/// `z_owned_closure_reply_t` and the same `crate::get::fire_reply` marshal that
/// `z_get` uses, rather than a parallel one.
///
/// Consumes the moved closure on EVERY path (pico's contract), and because the
/// C `drop(context)` IS the completion signal, an early error correctly reports
/// "this snapshot is over".
///
/// Fanned across every leg the engine reaches for the reason every declaration in
/// this crate is: one C session can be N per-face wz sessions, and a snapshot that
/// polled only the first face would silently under-report. The C thread holds
/// the get's place as its owner across the fan so a leg that answers and
/// finalises early cannot complete the get while later legs are still being
/// issued — the discipline of [`crate::get`]'s fan, which this one is. The
/// place is one of the session's pending liveliness gets
/// (`MAX_PENDING_LIVELINESS_GETS`), refused with `_Z_ERR_SYSTEM_OUT_OF_MEMORY`
/// when every one is held.
#[cfg(feature = "liveliness-get")]
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_get(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut crate::get::z_moved_closure_reply_t,
    options: *mut z_liveliness_get_options_t,
) -> ZResult {
    guarded(|| {
        // R311y575 — the moved cancellation token is consumed BEFORE the
        // null-callback return, which is a path it must also be freed on:
        // upstream drops it unconditionally once the call is made
        // (`src/api/liveliness.c:146`), so taking it later would leak one token
        // per `z_liveliness_get(zs, ke, NULL, &opts)`.
        let token = if options.is_null() {
            None
        } else {
            (*options).take_cancellation_token()
        };
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        // Adopt the closure FIRST and null the source (consume-on-all-paths).
        let mut closure = crate::get::adopt_reply_closure(callback);

        // A closed session issues no get; the closure adopted above runs its drop.
        let handle = match crate::session::open_session_handle(zs) {
            Ok(handle) => handle,
            Err(code) => return code,
        };
        // The session's close waits for this get's closure to finish and be dropped, and the place
        // of its handle stands until then.
        crate::session::count_in_session(zs, &mut closure);
        let ke = match crate::keyexpr::outbound_keyexpr(keyexpr) {
            Ok(k) => k,
            Err(code) => return code,
        };
        // A NULL options pointer is pico's "defaults", not an error.
        let timeout_ms = if options.is_null() {
            0
        } else {
            (*options).timeout_ms
        };
        // wz's field is a `u32`; saturate rather than wrap, for the reason
        // `crate::get::get_timeout_ms` records — a wrapped huge timeout becomes
        // a tiny one and expires the snapshot immediately.
        let timeout_ms = timeout_ms.min(u32::MAX as u64) as u32;

        // A liveliness reply's keyexpr is the TOKEN's, which intersects the
        // interest by construction; the gate is carried anyway so this plane
        // uses the same admission rule as `z_get` rather than a second one that
        // could drift.
        // The gate keeps the one copy of the key the get asks under, where the session keeps its
        // keys, and the get is sent naming the gate's, as `z_get` sends its own: one text.
        let engine = engine_held(handle);
        let gate = match crate::keyexpr::KeyText::of_session(engine, ke) {
            Ok(query_keyexpr) => crate::get::ReplyGate {
                query_keyexpr,
                anyke: false,
            },
            Err(code) => return code,
        };

        // The place, the cancellation, each leg's ownership and the order they drop in are the
        // fan's, shared with `z_get` (R311y575, R2949): registered BEFORE the first leg is
        // issued, as upstream does (`src/net/liveliness.c:341` registers it before
        // `_z_send_n_msg`), an already cancelled token answering `Z_ERR_CANCELLED` with no
        // Interest sent.
        crate::get::fan_get(
            engine,
            crate::object_slot::Kind::LivelinessGet,
            closure,
            gate,
            token.map(wz_capi_port::cancellation::TokenRef::shared),
            |asked, fan, leg| {
                engine.liveliness_get_on_wire(asked, &WireKey::literal(), timeout_ms, fan, leg)
            },
        )
    })
}

/// The pico sample kind for a wz liveliness event.
pub(crate) fn liveliness_kind_of(kind: LivelinessSampleKind) -> crate::pubsub::z_sample_kind_t {
    match kind {
        LivelinessSampleKind::Put => Z_SAMPLE_KIND_PUT,
        LivelinessSampleKind::Delete => Z_SAMPLE_KIND_DELETE,
    }
}

/// Declare a session-lifetime liveliness subscriber with no handle (pico
/// `z_liveliness_declare_background_subscriber`).
///
/// R311y559 — the BACKGROUND form of [`z_liveliness_declare_subscriber`]. It
/// takes the same arguments minus the handle slot and installs the same
/// subscription; the difference is ownership, not behaviour. Its closure lies in
/// its row, as an owned subscriber's does, and its place goes back at once; the
/// row holds the session's count open until it lets the closure go, so the close
/// waits for it.
///
/// # Safety
/// `zs` must be null or a live loaned session; `keyexpr` must be null or a live
/// loaned keyexpr; `callback` must be a valid moved closure, consumed on every
/// path; `options` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_declare_background_subscriber(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut z_liveliness_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        match declare_liveliness_subscriber_with(zs, keyexpr, callback, options, true) {
            Ok(state) => {
                // No handle will undeclare it: its owner lets go of the place at once, with no
                // wait, and the row keeps the closure until the session's close lets it go.
                crate::object_slot::release_entity(state);
                Z_OK
            }
            Err(code) => code,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use wz_session_core::declare::liveliness_sample::LivelinessSample;

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    /// The kind of the last sample the C callback was handed.
    static KIND: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn noted(
        sample: *const crate::pubsub::z_loaned_sample_t,
        context: *mut c_void,
    ) {
        assert_eq!(context as usize, 0x5c, "the program's context");
        // SAFETY: the sample the sink handed, valid for this call.
        let kind = unsafe { crate::pubsub::z_sample_kind(sample) };
        KIND.store(kind as usize, Ordering::SeqCst);
        CALLS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn dropped(context: *mut c_void) {
        assert_eq!(context as usize, 0x5c, "the program's context");
        DROPS.fetch_add(1, Ordering::SeqCst);
    }

    /// The callback a liveliness subscriber's row holds hands each change to the program's C
    /// callback, as a sample of the change's kind, and letting it go runs the C drop once. Turned
    /// red by a sink that calls nothing, one that hands the wrong kind, or one whose drop is not
    /// the closure's.
    #[test]
    fn a_liveliness_rows_callback_calls_the_c_closure_it_holds_and_drops_it_once() {
        let context = 0x5c_usize as *mut c_void;
        let closure = CClosure::uncounted(context, Some(noted), Some(dropped));
        let sink = liveliness_sink(closure, None);
        sink.call(LivelinessSample {
            kind: LivelinessSampleKind::Delete,
            keyexpr: "demo/alive",
            token_id: 1,
        });
        assert_eq!(CALLS.load(Ordering::SeqCst), 1, "the change handed");
        assert_eq!(
            KIND.load(Ordering::SeqCst),
            Z_SAMPLE_KIND_DELETE as usize,
            "as a sample of its kind"
        );
        assert_eq!(DROPS.load(Ordering::SeqCst), 0);
        drop(sink);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1, "the C drop ran once");
    }
}

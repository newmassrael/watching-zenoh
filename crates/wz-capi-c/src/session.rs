// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_open`, the session ownership family, and the mapping of an open's refusals onto zenoh-c's
//! codes.
//!
//! Neither the drive machinery nor the reading of the config is here. The drive is
//! [`wz_capi_core::drive`], shared with the zenoh-pico ABI, and what a config
//! document means for an open (the role, the endpoints, the phases, the security, and every
//! refusal) is [`wz_capi_core::open_plan::OpenPlan`], one value for every client of the engine.
//! This module is only the shim: hand the core the keys this ABI's flat config store holds, add
//! the choices that are zenoh-c's (how it transmits, who runs a local delivery's callbacks, how its
//! faces are driven), and map the core's neutral refusals and failures onto zenoh-c's codes.

use std::ffi::c_void;

use wz_capi_core::drive::{FaceDrive, OpenError, SessionState};
use wz_capi_core::faces::{no_shm_clients, OpenShmClients};
use wz_capi_core::open_plan::{dial_role, AbiChoices, OpenPlan, OpenRefusal, StatedEndpoints};
use wz_runtime_tokio::session::LocalDeliveryDrain;
use wz_runtime_tokio::session_glue::TxQueueConf;

use crate::abi::{
    z_loaned_session_t, z_moved_config_t, z_moved_session_t, z_owned_session_t, Handle,
};
use crate::config::{config_state, ConfigState, CONNECT_KEY, LISTEN_KEY, MODE_KEY};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_EINVAL, Z_ENETWORK, Z_ENULL, Z_OK};

/// Read the [`SessionState`] behind a loaned session.
///
/// # Safety
/// `zs` must be null, or a valid loaned session whose handle slot holds a live
/// `Box::into_raw::<SessionState>` pointer (what [`z_open`] installs).
pub(crate) unsafe fn session_state<'a>(zs: *const z_loaned_session_t) -> Option<&'a SessionState> {
    if zs.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*zs).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `Box<SessionState>` this crate leaked.
    Some(unsafe { &*(handle as *const SessionState) })
}

/// Construct and open a session, consuming the moved config (zenoh-c `z_open`).
///
/// # Safety
/// `this_` must be valid and writable; `config` must be a valid moved config.
/// `_options` is accepted for ABI compatibility and ignored — zenoh-c's
/// `z_open_options_t` is a single `uint8_t _dummy` at this version.
#[no_mangle]
pub unsafe extern "C" fn z_open(
    this_: *mut z_owned_session_t,
    config: *mut z_moved_config_t,
    _options: *const c_void,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    guarded(|| unsafe { open_session(this_, config, no_shm_clients()) })
}

/// What a refusal of the open is, in zenoh-c's two codes.
///
/// A configuration the open refuses for what it STATES (a key it cannot hold, a file it cannot
/// read, a role the build does not have) is `Z_EINVAL`, and one that reaches an open which cannot
/// be established (nothing to dial, a group where a link is needed, a transport that refuses its
/// own offer, a gossip target upstream refuses at open) is `Z_ENETWORK`, as the same configs are
/// on the real library. The match is exhaustive: a new refusal must choose.
fn refusal_code(refusal: OpenRefusal) -> ZResult {
    match refusal {
        OpenRefusal::DocumentUnreadable
        | OpenRefusal::Security
        | OpenRefusal::TlsMaterial
        | OpenRefusal::ZenohId
        | OpenRefusal::Scouting
        | OpenRefusal::RoleNotInBuild
        | OpenRefusal::TimestampingNotInBuild
        | OpenRefusal::Namespace => Z_EINVAL,
        OpenRefusal::QosWithLowlatency
        | OpenRefusal::GossipTarget
        | OpenRefusal::NothingToDial
        | OpenRefusal::GroupInConnect
        | OpenRefusal::NoDialableEndpoint => Z_ENETWORK,
    }
}

/// What this ABI decides about an open, beyond what the config says.
///
/// zenoh's own bounded queue and waits: this ABI stands for zenoh-c.
fn abi_choices(shm_clients: OpenShmClients) -> AbiChoices {
    AbiChoices {
        tx_queue: TxQueueConf::default(),
        // zenoh-c has no switch for a session's read task: its runtime drives the session from
        // the open.
        start_read_task: true,
        // R3069 -- zenoh-c runs the callbacks of a delivery a session makes to itself INSIDE the
        // call that causes it, on the calling thread (measured: a put's subscriber, a get's
        // queryable and its reply, and a put made from inside a callback, all complete before the
        // call returns). A callback may therefore run on the thread that called, as well as on
        // the drive thread for what arrives from a peer; a C program written for zenoh-c already
        // tolerates both, and one that puts and then reads what its callback set relies on the
        // first.
        local_delivery: LocalDeliveryDrain::Caller,
        // zenoh's session tells its own liveliness subscribers of its own tokens, and its own
        // liveliness get finds them.
        liveliness_to_self: true,
        // R3073 -- zenoh-c's peer ends what it sends a new peer with the initial interest's
        // Final, and the open of a zenoh peer that dials this one waits for it.
        initial_interest: true,
        // zenoh-c's callbacks are concurrent across links (`CClosure` is `Sync`): its receive
        // runtime serves each link on its own, and a callback that blocks holds up its link and
        // no other. A face of this session has a thread of its own.
        face_drive: FaceDrive::PerFace,
        shm_clients,
        // R3052 -- shared memory is offered at the handshake on the shared-memory arm (the
        // condition the `shm` module itself has), and a node's multicast transports are reported
        // as shared-memory ones wherever the build carries the axis (MEASURED: the real library's
        // `z_info` printed `is_shm: true` for a zenohd member).
        offer_shm: cfg!(all(
            feature = "zenoh-c-shared-memory",
            not(feature = "zenoh-c-no-unstable-api")
        )),
        groups_report_shm: cfg!(feature = "zenoh-c-shared-memory"),
    }
}

/// The endpoints the flat config store states for this open: `connect/endpoints` is the whole
/// list (R2948: each endpoint is dialled on its own schedule) and `listen/endpoints` is what the
/// store holds, empty when it holds none (the plan then asks the document).
fn stated_endpoints(cfg: &ConfigState) -> StatedEndpoints {
    let all = |key| cfg.all(key).into_iter().map(str::to_owned).collect();
    StatedEndpoints {
        connect: all(CONNECT_KEY),
        listen: all(LISTEN_KEY),
    }
}

/// The plan an open of `cfg` runs: the one reading of a config that [`open_session`] opens and
/// [`wz_capi_c_config_device_requires`] describes, so the two cannot read a document differently.
///
/// The document is read for the role the session DIALS as, because several keys are
/// mode-dependent upstream ([`ConfigState::with_default_mode`]). It goes through wz's one reader
/// of a stock config, in the plan.
fn plan_of(cfg: &ConfigState) -> Result<OpenPlan, OpenRefusal> {
    let role = dial_role(cfg.first(MODE_KEY));
    let stated = stated_endpoints(cfg);
    let document = cfg.with_default_mode(role.to_str()).render_nested().ok();
    OpenPlan::resolve(role, stated, document.as_deref())
}

/// What an open of `config` would ask of the operating system, as one JSON object with the keys of
/// the target-build manifest (docs/target-build-contract.md T9): `requires` (what every run of it
/// cannot go on without), `may_require` (the rest it may ask for, `null` when part of it has no
/// name) and `unknown` (why it has none). It reads the config through the same plan [`z_open`]
/// runs, and does not consume it.
///
/// A config the open would refuse returns that refusal's code, and the string names it with the
/// keys at fault: no requirement is written for an open that would not happen.
///
/// # Safety
/// `config` must be null or a valid loaned config; `out_requirement` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_device_requires(
    config: *const crate::abi::z_loaned_config_t,
    out_requirement: *mut crate::abi::z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if out_requirement.is_null() {
            return Z_ENULL;
        }
        // SAFETY: checked non-null above.
        unsafe { *out_requirement = crate::string::null_string() };
        // SAFETY: the caller's contract; the config is only read.
        let Some(cfg) = (unsafe { config_state(config.cast_mut()) }) else {
            return Z_ENULL;
        };
        let (text, code) = match plan_of(cfg) {
            Ok(plan) => (plan.device_requires().to_json(), Z_OK),
            Err(refusal) => (
                format!(
                    "{refusal:?}: the open refuses this configuration ({})",
                    refusal.key()
                ),
                refusal_code(refusal),
            ),
        };
        // SAFETY: checked non-null above.
        unsafe { *out_requirement = crate::string::owned_string_from(text.as_bytes()) };
        code
    })
}

/// The open `z_open` and `z_open_with_custom_shm_clients` both are: the same config, the same
/// refusals and the same session, over `shm_clients` as its shared-memory reader (R3065). The
/// default is the reader every session had before this crate could be given one, POSIX alone.
///
/// # Safety
/// As [`z_open`].
pub(crate) unsafe fn open_session(
    this_: *mut z_owned_session_t,
    config: *mut z_moved_config_t,
    shm_clients: OpenShmClients,
) -> ZResult {
    if this_.is_null() || config.is_null() {
        return Z_ENULL;
    }
    // The gravestone contract, and zenoh-c states it explicitly: on failure
    // "the session will be in its gravestone state". Written BEFORE any
    // fallible work so it holds on every error path.
    unsafe { *this_ = z_owned_session_t::null_value() };

    // z_open CONSUMES the config: reclaim it and null the source, so a
    // defensive later `z_config_drop` is a safe no-op.
    let loaned = unsafe { &raw mut (*config)._this } as *mut crate::abi::z_loaned_config_t;
    let Some(cfg) = (unsafe { config_state(loaned) }) else {
        return Z_ENULL;
    };
    // Everything the document decides, and every refusal, before anything is bound or dialled.
    let plan = plan_of(cfg);
    let handle = unsafe { (*config)._this.handle };
    // SAFETY: a live `Box<ConfigState>` this crate leaked; consumed here.
    drop(unsafe { Box::from_raw(handle as *mut ConfigState) });
    unsafe { (*config)._this = crate::abi::z_owned_config_t::null_value() };
    let plan = match plan {
        Ok(plan) => plan,
        Err(refusal) => return refusal_code(refusal),
    };
    #[cfg(all(
        feature = "zenoh-c-shared-memory",
        not(feature = "zenoh-c-no-unstable-api")
    ))]
    let shm_keys = plan.shm;
    #[allow(unused_mut)]
    let mut arguments = plan.into_arguments(abi_choices(shm_clients));
    // R3065 -- a session opened over a client storage advertises the protocols of THAT
    // reader: the stance takes both from the one set, so the list a peer's sender reads is
    // never wider than what the session resolves.
    #[cfg(feature = "zenoh-c-shared-memory")]
    if let Some(set) = arguments.stance.shm_clients.clone() {
        arguments.stance = match arguments.stance.with_shm_clients(set) {
            Ok(stance) => stance,
            // More protocols than an auth segment has slots for: upstream's
            // `AuthUnicast::new` refuses it, which fails the open.
            Err(_) => return Z_ENETWORK,
        };
    }
    match arguments.run() {
        Ok(state) => {
            // R2957 — the session's own shared-memory provider, as its
            // config states it; built on first ask, as upstream's is.
            #[cfg(all(
                feature = "zenoh-c-shared-memory",
                not(feature = "zenoh-c-no-unstable-api")
            ))]
            let _ = state.set_abi_extension(crate::shm::SessionShm::from_config(
                shm_keys.enabled,
                shm_keys.transport_optimization,
                shm_keys.pool_size,
            ));
            let h = Box::into_raw(Box::new(state)) as Handle;
            unsafe { *this_ = z_owned_session_t::from_handle(h) };
            Z_OK
        }
        // The core reports a NEUTRAL failure; zenoh-c's vocabulary for "the
        // session could not be established" is Z_ENETWORK, whichever the cause.
        Err(OpenError::DriveFailed | OpenError::LinkFailed | OpenError::SchemeUnknown) => {
            Z_ENETWORK
        }
    }
}

/// Close a session (zenoh-c `z_close`): stop the drive loop and join its thread.
/// Does not free the owned struct — that is [`z_session_drop`].
///
/// # Safety
/// `session` must be null or a valid loaned session.
#[no_mangle]
pub unsafe extern "C" fn z_close(
    session: *mut z_loaned_session_t,
    _options: *mut c_void,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        match unsafe { session_state(session) } {
            Some(state) => {
                state.close();
                Z_OK
            }
            None => Z_ENULL,
        }
    })
}

/// `true` iff the owned session holds a live handle (zenoh-c
/// `z_internal_session_check`).
///
/// # Safety
/// `this_` must be null or a valid owned session.
#[no_mangle]
pub unsafe extern "C" fn z_internal_session_check(this_: *const z_owned_session_t) -> bool {
    guard_val(false, || {
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned session (zenoh-c `z_internal_session_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned session.
#[no_mangle]
pub unsafe extern "C" fn z_internal_session_null(this_: *mut z_owned_session_t) {
    if !this_.is_null() {
        unsafe { *this_ = z_owned_session_t::null_value() };
    }
}

/// Borrow a session immutably (zenoh-c `z_session_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned session.
#[no_mangle]
pub unsafe extern "C" fn z_session_loan(
    this_: *const z_owned_session_t,
) -> *const z_loaned_session_t {
    this_ as *const z_loaned_session_t
}

/// Borrow a session mutably (zenoh-c `z_session_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned session.
#[no_mangle]
pub unsafe extern "C" fn z_session_loan_mut(
    this_: *mut z_owned_session_t,
) -> *mut z_loaned_session_t {
    this_ as *mut z_loaned_session_t
}

/// Drop an owned session (zenoh-c `z_session_drop`): closes if not already, then
/// frees the [`SessionState`].
///
/// # Safety
/// `this_` must be null or a valid moved session whose handle is live.
#[no_mangle]
pub unsafe extern "C" fn z_session_drop(this_: *mut z_moved_session_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SessionState::drop runs close() (idempotent).
            // SAFETY: a live `Box<SessionState>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut SessionState) });
            unsafe { (*this_)._this = z_owned_session_t::null_value() };
        }
        Z_OK
    });
}

/// zenoh-c's `z_open_options_t` (`zenoh_commons.h:883-885`) — a placeholder.
///
/// Declared rather than taken as `void*` so a C program using the documented
/// shape compiles, and so the footprint gate can measure it.
#[repr(C)]
pub struct z_open_options_t {
    /// Upstream's own name for the placeholder byte.
    pub _dummy: u8,
}

/// zenoh-c's `z_close_options_t` (`zenoh_commons.h:473-491`).
///
/// FEATURE-DEPENDENT, like the publisher options: `Z_FEATURE_UNSTABLE_API`
/// replaces the placeholder byte with a close timeout and a concurrent-close
/// handle out-pointer.
#[repr(C)]
pub struct z_close_options_t {
    /// The close timeout in milliseconds; 0 means upstream's default of 10 s.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub internal_timeout_ms: u32,
    /// An optional out-pointer for a concurrent-close handle. wz closes
    /// synchronously, so a non-null request here is ACCEPTED and the handle is
    /// left untouched — a named divergence rather than a silent one, and the
    /// shape a caller who never sets it cannot observe.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub internal_out_concurrent: *mut c_void,
    /// Upstream's placeholder on the no-unstable arm.
    #[cfg(feature = "zenoh-c-no-unstable-api")]
    pub _dummy: u8,
}

/// Upstream's defaults for `z_open_options_t` (zenoh-c `z_open_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_open_options_default(this_: *mut z_open_options_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_open_options_t { _dummy: 0 } };
    }
}

/// Upstream's defaults for `z_close_options_t` (zenoh-c
/// `z_close_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_close_options_default(this_: *mut z_close_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_close_options_t {
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            internal_timeout_ms: 0,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            internal_out_concurrent: std::ptr::null_mut(),
            #[cfg(feature = "zenoh-c-no-unstable-api")]
            _dummy: 0,
        }
    };
}

// --- R311y568: the CONCURRENT-CLOSE handle family ---------------------------

/// zenoh-c `zc_owned_concurrent_close_handle_t` — 16 bytes at align 8, MEASURED
/// against the unstable oracle's header (it is declared on that arm only, which
/// is why the whole family is unstable-gated here as upstream gates it).
///
/// ## wz closes SYNCHRONOUSLY, so this handle is always a gravestone
///
/// [`z_close_options_t::internal_out_concurrent`] already records the divergence:
/// wz's close runs to completion inside `z_close`, so there is no separate task
/// to control and the out-param is left untouched. The four functions below are
/// therefore the operations on a handle that is never non-null.
///
/// That is not a stub. Upstream's contract for an uninitialised handle is that
/// `zc_internal_concurrent_close_handle_check` reads `false`, `_wait` has nothing
/// to wait for, and `_drop` is a no-op — which is exactly what a C program that
/// never set the option gets from upstream too, and exactly what it gets here
/// whether or not it set it. Their absence, by contrast, was a LINK error for any
/// program that named them.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[repr(C)]
pub struct zc_owned_concurrent_close_handle_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; 8],
}

/// Moved concurrent-close handle (zenoh-c `zc_moved_concurrent_close_handle_t`).
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[repr(C)]
pub struct zc_moved_concurrent_close_handle_t {
    pub(crate) _this: zc_owned_concurrent_close_handle_t,
}

#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
const _: () = {
    assert!(std::mem::size_of::<zc_owned_concurrent_close_handle_t>() == 16);
    assert!(std::mem::align_of::<zc_owned_concurrent_close_handle_t>() == 8);
    assert!(std::mem::size_of::<zc_moved_concurrent_close_handle_t>() == 16);
};

#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
impl zc_owned_concurrent_close_handle_t {
    /// The gravestone value — the only value wz ever produces.
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [0u8; 8],
        }
    }
}

/// Wait for a concurrent close to finish (zenoh-c
/// `zc_concurrent_close_handle_wait`).
///
/// `Z_OK` on a gravestone, which is the honest answer rather than a convenient
/// one: wz's `z_close` has ALREADY completed by the time it returns, so "the
/// close this handle refers to has finished" is true. Reporting an error would
/// tell a C program its session failed to close when it did.
///
/// # Safety
/// `handle` must be null or a valid moved concurrent-close handle.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn zc_concurrent_close_handle_wait(
    handle: *mut zc_moved_concurrent_close_handle_t,
) -> crate::result::ZResult {
    // SAFETY: the caller's contract, delegated — the handle is consumed either
    // way, as a `zc_moved_*` parameter must be.
    unsafe { zc_concurrent_close_handle_drop(handle) };
    crate::result::Z_OK
}

/// Free a concurrent-close handle (zenoh-c `zc_concurrent_close_handle_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved concurrent-close handle.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn zc_concurrent_close_handle_drop(
    this_: *mut zc_moved_concurrent_close_handle_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract. Gravestoned on every path, so a
        // defensive second drop is a no-op.
        unsafe { (*this_)._this = zc_owned_concurrent_close_handle_t::null_value() };
    }
}

/// `true` iff the handle refers to a live concurrent close (zenoh-c
/// `zc_internal_concurrent_close_handle_check`).
///
/// Always `false` here — see the type's docs.
///
/// # Safety
/// `this_` must be null or a valid owned concurrent-close handle.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn zc_internal_concurrent_close_handle_check(
    this_: *const zc_owned_concurrent_close_handle_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero a concurrent-close handle (zenoh-c
/// `zc_internal_concurrent_close_handle_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned concurrent-close handle.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn zc_internal_concurrent_close_handle_null(
    this_: *mut zc_owned_concurrent_close_handle_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = zc_owned_concurrent_close_handle_t::null_value() };
    }
}

/// The last error this thread recorded, as a view string (zenoh-c
/// `zc_get_last_error`).
///
/// wz records none: every entry point in this crate reports its verdict through
/// its `z_result_t` return, and [`crate::ffi`] maps even a panic onto
/// `Z_EINVAL` rather than stashing a message. So this writes the EMPTY view,
/// which is upstream's own answer when nothing has failed.
///
/// The divergence is that a wz caller learns nothing MORE from this than the
/// return code already told them — never something different, and never a stale
/// message from an unrelated call, which is the failure mode a thread-local
/// error string has.
///
/// UNSTABLE-gated, because upstream gates it (`zenoh_commons.h:5774`).
///
/// # Safety
/// `out` must be null or valid and writable.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn zc_get_last_error(out: *mut crate::abi::z_view_string_t) {
    if !out.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *out = crate::abi::z_view_string_t::null_value() };
    }
}

/// `true` iff the session has been closed (zenoh-c `z_session_is_closed`).
///
/// R311y564 — the accessor existed on `SessionState` from the day the drive
/// loop was written, and its doc comment named this very export; only the
/// `#[no_mangle]` wrapper was missing, so a C program asking the question did
/// not link. A null or gravestoned handle reads as CLOSED, which is the safe
/// direction: there is no live session behind it.
///
/// # Safety
/// `session` must be null or a valid loaned session.
#[no_mangle]
pub unsafe extern "C" fn z_session_is_closed(session: *const z_loaned_session_t) -> bool {
    guard_val(true, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { session_state(session) }.map_or(true, SessionState::is_closed)
    })
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_open`, the session ownership family, and the config -> role mapping.
//!
//! The drive machinery is NOT here: it is
//! [`wz_capi_core::drive`](wz_capi_core::drive), shared with the zenoh-pico ABI.
//! This module is only the shim — read the config, pick a role, hand it to the
//! core, and map the core's neutral error onto zenoh-c's codes.

use std::ffi::c_void;

use wz_capi_core::drive::{
    open_blocking, CapiTlsConfig, ConfiguredZid, DialPhase, OpenError, OpenStance, SessionState,
};
use wz_capi_core::faces::{no_shm_clients, OpenShmClients};
use wz_runtime_tokio::node_clock::TimestampingEnabled;
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::session_glue::{TxQueueConf, WhatAmI};
use wz_runtime_tokio::session_open::{SessionOffer, TransportMode};
use wz_runtime_tokio::startup_phase::PhasePolicy;
use wz_runtime_tokio::zenoh_config::{ZenohConfigIngest, ZenohNodeConfig};

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

/// zenoh-c's `mode` values map onto wz roles.
///
/// Default PEER, which is zenoh's own default when the key is absent
/// (`commons/zenoh-config/src/defaults.rs` @ `pub const mode: WhatAmI = WhatAmI::Peer;`).
/// It said CLIENT until R2948 while claiming to match zenoh, and a config that
/// named no mode dialled with a client's one-attempt budget where zenoh-c's
/// peer keeps trying behind the open.
fn dial_whatami(cfg: &ConfigState) -> WhatAmI {
    match cfg.first(MODE_KEY) {
        Some("client") => WhatAmI::Client,
        Some("router") => WhatAmI::Router,
        _ => WhatAmI::Peer,
    }
}

/// How the dial keeps trying, read from the config the way a zenoh node reads
/// it.
///
/// `connect/timeout_ms` and `connect/exit_on_failure` are mode-dependent
/// upstream, and so are their defaults: a client makes ONE attempt, a peer or
/// router retries without bound. Both are resolved for the role this session
/// DIALS as, which is why the document is read with that role stated — see
/// [`ConfigState::with_default_mode`]. `connect/retry` paces the attempts and
/// falls back to upstream's 1s / 2s / 4s.
///
/// Read from the document [`read_node`] parsed.
fn dial_phase(node: &ZenohNodeConfig, whatami: WhatAmI) -> DialPhase {
    let default = PhasePolicy::connect_default_for(whatami);
    let schedule = node.connect_retry.unwrap_or(RetryPolicy::ZENOH_DEFAULT);
    DialPhase {
        policy: PhasePolicy {
            budget: node.connect_timeout_ms.unwrap_or(default.budget),
            exit_on_failure: node
                .connect_exit_on_failure
                .unwrap_or(default.exit_on_failure),
        },
        schedule,
        // R2948 — zenoh re-dials a lost session's endpoints on the same
        // `connect/retry` block, with no budget.
        redial: Some(schedule),
        // R2950 — a peer's open waits `scouting/delay` for its background
        // endpoints unless `open/return_conditions/connect_scouted` is false;
        // upstream's defaults are 500 ms and true.
        start_window: node
            .open_connect_scouted
            .unwrap_or(true)
            .then(|| std::time::Duration::from_millis(node.scouting_delay_ms.unwrap_or(500))),
    }
}

/// Why a config cannot be offered: it enables both halves of the one exclusive
/// transport choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QosWithLowlatency;

/// What this session's links offer at their handshake, read from its config
/// the way zenoh's transport manager reads it.
///
/// Upstream builds the unicast half from three keys
/// (`io/zenoh-transport/src/unicast/manager.rs` @
/// `self = self.qos(*config.transport().unicast().qos().enabled());`, the
/// lowlatency line after it, and the compression line behind
/// `transport_compression`, which zenoh-c's default build carries). Both the
/// dialling and the accepting side read the same manager config, so one value
/// serves both.
///
/// The defaults are upstream's, and QoS is ON: an unconfigured zenoh-c session
/// offers it. A session that offered nothing — what this ABI did until R2970 —
/// agreed on no QoS with another zenoh-c session, where two real ones do.
///
/// QoS and lowlatency together are refused, as upstream's manager refuses them
/// when it is built (`bail!("'qos' and 'lowlatency' options are incompatible");`),
/// which is inside `zenoh::open` and so reaches a C caller as an open failure.
///
/// ## Shared memory is offered on the shared-memory arm (R3052)
///
/// Upstream's shared-memory build also offers SHM, from
/// `transport/shared_memory/enabled`
/// (`io/zenoh-transport/src/common/shm/shm_context.rs` @ `if !*cfg.enabled() {`),
/// default on, and so does this session on the arm that carries the axis
/// (`zenoh-c-shared-memory` without `zenoh-c-no-unstable-api`, the condition the
/// `shm` module itself has): the offer is `node.shared_memory`. Until R3052 it did
/// not, on any arm, because a Put carrying a shared-memory buffer is laid out as
/// slices on the wire, which wz's generated Put codec could not read (open-debt
/// item 823), so a session that agreed on SHM would have lost every such sample.
/// The codec reads the layout now, and a payload a peer sends as shared memory is
/// delivered as the page it lies on, so `z_bytes_as_loaned_shm` answers for it.
/// Without the axis there is no shared memory to offer.
fn session_offer(node: &ZenohNodeConfig) -> Result<SessionOffer, QosWithLowlatency> {
    let mode = match (node.qos, node.lowlatency) {
        (true, true) => return Err(QosWithLowlatency),
        (true, false) => TransportMode::Qos,
        (false, true) => TransportMode::LowLatency,
        (false, false) => TransportMode::Universal,
    };
    #[allow(unused_mut)]
    let mut offer = SessionOffer::universal()
        .with_mode(mode)
        .with_compression(node.compression);
    #[cfg(all(
        feature = "zenoh-c-shared-memory",
        not(feature = "zenoh-c-no-unstable-api")
    ))]
    {
        offer = offer.with_shm(node.shared_memory);
    }
    Ok(offer)
}

/// The session's configuration, read ONCE, the way a zenoh node reads it.
///
/// The document goes through [`ZenohNodeConfig::from_json5`], wz's one reader
/// of a stock config, rather than a second reading of a few keys here — the
/// dial phase and (R2957) the shared-memory provider both read the result. It
/// is read for the role this session DIALS as, because several keys are
/// mode-dependent upstream ([`ConfigState::with_default_mode`]). A config that
/// reader refuses (a key zenoh does not have, two keys that cannot both be
/// nested, a value out of range) is refused by the open too, which is where
/// upstream stands: its insert refuses the same keys before an open is reached.
fn read_node(cfg: &ConfigState, whatami: WhatAmI) -> Option<ZenohConfigIngest> {
    let document = cfg
        .with_default_mode(whatami.to_str())
        .render_nested()
        .ok()?;
    ZenohNodeConfig::from_json5(&document).ok()
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
    {
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
        // R2948 — the whole list; each endpoint is dialled on its own schedule.
        let connect: Vec<String> = cfg
            .all(CONNECT_KEY)
            .into_iter()
            .map(str::to_owned)
            .collect();
        let listen = cfg.first(LISTEN_KEY).map(str::to_owned);
        let whatami = dial_whatami(cfg);
        let ingest = read_node(cfg, whatami);
        // R3064 -- the clock map the document means. Read off the ingest and not the node
        // config, because only the ingest knows whether the key was NAMED: the field reads
        // `false` for a document that never mentioned it, and a router's own default is on.
        let timestamping = ingest.as_ref().map_or_else(
            TimestampingEnabled::default,
            ZenohConfigIngest::timestamping_enabled,
        );
        let node = ingest.map(|ingest| ingest.config);
        let phase = node.as_ref().map(|node| dial_phase(node, whatami));
        let handle = unsafe { (*config)._this.handle };
        // SAFETY: a live `Box<ConfigState>` this crate leaked; consumed here.
        drop(unsafe { Box::from_raw(handle as *mut ConfigState) });
        unsafe { (*config)._this = crate::abi::z_owned_config_t::null_value() };

        // The id this config STATES for its session, if it states one. Read off
        // the node the reader already parsed, so a config's `id` is one value
        // whether it arrived by an insert, by a document or from a file, and the
        // session stands on it: `z_info_zid` reports it and the INIT carries it,
        // which is what upstream's runtime does with the same key.
        //
        // The insert doors refuse text zenoh refuses, as upstream's do, so an
        // unparsable `id` cannot be in a config those built. It is refused here
        // as well, rather than met with a fresh random id, because a config that
        // named an identity and got another would be the silent fallback this
        // crate refuses everywhere else.
        let zid = match node.as_ref().and_then(|node| node.id.as_deref()) {
            None => None,
            Some(text) => match ConfiguredZid::from_zenoh_text(text) {
                Some(zid) => Some(zid),
                None => return Z_EINVAL,
            },
        };

        // Decided before anything else about the open, as upstream decides it
        // when the transport manager is built — before a single endpoint is
        // looked at. A config the reader refused has no offer to derive; the
        // `phase` check below refuses that open.
        let offer = match node.as_ref().map(session_offer).transpose() {
            Ok(offer) => offer.unwrap_or_else(SessionOffer::universal),
            Err(QosWithLowlatency) => return Z_ENETWORK,
        };

        // A config with neither endpoint is a scouting open, which this slice
        // does not implement. Refused rather than silently opening a session
        // that reaches nothing.
        if connect.is_empty() && listen.is_none() {
            return Z_EINVAL;
        }
        // Both is zenoh's dual-role peer; the core drives one role per session,
        // so refuse rather than silently dropping the listener.
        if !connect.is_empty() && listen.is_some() {
            return Z_EINVAL;
        }
        // Checked after the two refusals above so a config that states no
        // endpoint keeps answering what it always did.
        let Some(phase) = phase else {
            return Z_EINVAL;
        };

        // R311y534 — `CapiTlsConfig::default()` is the cert-free tcp/udp/ws open,
        // which is every open this ABI currently parses: zenoh-c's config is a
        // JSON5 document whose `transport/link/tls` block this slice does not
        // read yet. The pico shim resolves its own numeric TLS keys and passes a
        // populated one; when this ABI grows the JSON path it fills the same
        // struct, which is why the parameter is typed rather than a pair of
        // `None`s that only ever meant "no quic cert".
        // zenoh's own bounded queue and waits: this ABI stands for zenoh-c.
        let stance = OpenStance {
            tx_queue: TxQueueConf::default(),
            offer,
            zid,
            // zenoh-c has no switch for a session's read task: its runtime
            // drives the session from the open.
            start_read_task: true,
            timestamping,
            shm_clients,
        };
        // R3065 -- a session opened over a client storage advertises the protocols of THAT
        // reader: the stance takes both from the one set, so the list a peer's sender reads is
        // never wider than what the session resolves.
        #[cfg(feature = "zenoh-c-shared-memory")]
        let stance = match stance.shm_clients.clone() {
            Some(set) => match stance.with_shm_clients(set) {
                Ok(stance) => stance,
                // More protocols than an auth segment has slots for: upstream's
                // `AuthUnicast::new` refuses it, which fails the open.
                Err(_) => return Z_ENETWORK,
            },
            None => stance,
        };
        match open_blocking(
            connect,
            listen,
            CapiTlsConfig::default(),
            whatami,
            phase,
            stance,
        ) {
            Ok(state) => {
                // R2957 — the session's own shared-memory provider, as its
                // config states it; built on first ask, as upstream's is.
                #[cfg(all(
                    feature = "zenoh-c-shared-memory",
                    not(feature = "zenoh-c-no-unstable-api")
                ))]
                if let Some(node) = node.as_ref() {
                    let _ = state.set_abi_extension(crate::shm::SessionShm::from_config(
                        node.shared_memory,
                        node.shm_transport_optimization,
                        node.shm_pool_size,
                    ));
                }
                let h = Box::into_raw(Box::new(state)) as Handle;
                unsafe { *this_ = z_owned_session_t::from_handle(h) };
                Z_OK
            }
            // The core reports a NEUTRAL failure; zenoh-c's vocabulary for "the
            // session could not be established" is Z_ENETWORK.
            Err(OpenError::DriveFailed) => Z_ENETWORK,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The offer for a config document, read by the one reader `z_open` uses.
    fn offer_for(document: &str) -> Result<SessionOffer, QosWithLowlatency> {
        let node = ZenohNodeConfig::from_json5(document)
            .expect("the document is one the reader accepts")
            .config;
        session_offer(&node)
    }

    /// What an offer holds beside the unicast keys under test: shared memory on the
    /// arm that carries that axis, because upstream's key defaults on and this
    /// session reads the key (R3052), and nothing on an arm that does not.
    fn with_the_arms_default(offer: SessionOffer) -> SessionOffer {
        #[cfg(all(
            feature = "zenoh-c-shared-memory",
            not(feature = "zenoh-c-no-unstable-api")
        ))]
        let offer = offer.with_shm(true);
        offer
    }

    /// R2970 — an unconfigured session offers QoS, upstream's default, and no
    /// other capability but the one its arm's defaults add (R3052: shared memory,
    /// on the arm that carries that axis).
    #[test]
    fn an_unconfigured_session_offers_qos_and_nothing_else() {
        assert_eq!(
            offer_for("{}"),
            Ok(with_the_arms_default(
                SessionOffer::universal().with_mode(TransportMode::Qos)
            ))
        );
    }

    /// Each unicast key reaches the offer on its own. Compression is the one
    /// half the C-level differential cannot see — no zenoh-c accessor reports
    /// it — so its staging is held here.
    #[test]
    fn each_unicast_key_reaches_the_offer() {
        assert_eq!(
            offer_for(r#"{ transport: { unicast: { qos: { enabled: false } } } }"#),
            Ok(with_the_arms_default(SessionOffer::universal()))
        );
        assert_eq!(
            offer_for(
                r#"{ transport: { unicast: { qos: { enabled: false }, lowlatency: true } } }"#
            ),
            Ok(with_the_arms_default(
                SessionOffer::universal().with_mode(TransportMode::LowLatency)
            ))
        );
        assert_eq!(
            offer_for(r#"{ transport: { unicast: { compression: { enabled: true } } } }"#),
            Ok(with_the_arms_default(
                SessionOffer::universal()
                    .with_mode(TransportMode::Qos)
                    .with_compression(true)
            ))
        );
    }

    /// QoS stays on by default, so lowlatency alone is the refused pair — the
    /// configuration upstream's manager refuses when it is built.
    #[test]
    fn lowlatency_with_the_default_qos_is_refused() {
        assert_eq!(
            offer_for(r#"{ transport: { unicast: { lowlatency: true } } }"#),
            Err(QosWithLowlatency)
        );
    }

    /// R3052 -- shared memory is offered from the node's key on the arm that carries
    /// the axis, and is never offered on one that does not: the offer was staged by
    /// no arm until the Put codec read the sliced layout, and this is the test that
    /// moved with that.
    #[test]
    fn shared_memory_is_offered_from_the_key_on_the_arm_that_carries_it() {
        let node = |enabled: bool| {
            ZenohNodeConfig::from_json5(&format!(
                r#"{{ transport: {{ shared_memory: {{ enabled: {enabled} }} }} }}"#
            ))
            .expect("the document is one the reader accepts")
            .config
        };
        assert!(node(true).shared_memory, "the reader carries the key");
        assert!(!node(false).shared_memory, "and carries it off");
        #[cfg(all(
            feature = "zenoh-c-shared-memory",
            not(feature = "zenoh-c-no-unstable-api")
        ))]
        {
            assert!(session_offer(&node(true)).expect("no mode conflict").shm);
            assert!(!session_offer(&node(false)).expect("no mode conflict").shm);
        }
        #[cfg(not(all(
            feature = "zenoh-c-shared-memory",
            not(feature = "zenoh-c-no-unstable-api")
        )))]
        assert!(!session_offer(&node(true)).expect("no mode conflict").shm);
    }
}

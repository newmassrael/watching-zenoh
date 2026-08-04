// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_open` / `z_close`, the session ownership family, and the `zp_*_task`
//! shims — plus the async-drive bridge that makes a wz `Session` behave like a
//! self-driving pico session.
//!
//! ## The drive bridge
//!
//! wz has no `Session::open` and no self-driving session: a subscriber
//! callback fires only while a drive loop actively pumps the link, dispatching
//! each `IterationEvent` into the observer the subscriber registered on. pico's
//! `z_open`, by contrast, returns and the read/lease work runs in the
//! background (`~/zenoh-pico/src/api/api.c:882-942` starts the background
//! executor inside `z_open`).
//!
//! This crate bridges that by owning one OS thread per session, running a
//! multi-thread tokio runtime that `block_on`s the whole session lifecycle.
//! `block_on` does not require the driven future to be `Send`, which the accept
//! loop's per-face drive futures are not; the runtime is multi-thread so the
//! socket writer tasks and the drive loop make progress while the C thread is
//! between calls.
//!
//! ## The two roles, and what `z_open` blocks on
//!
//! The config's `connect` / `listen` keys pick the role, and each mirrors what
//! real pico does:
//!
//! - **`connect` (dial, client)** — pico performs a synchronous outbound
//!   InitSyn/InitAck/OpenSyn/OpenAck handshake and returns success, or an error
//!   if the peer is unreachable (`src/transport/unicast/transport.c:280-287`).
//!   So `z_open` here blocks until Established and lands exactly one peer
//!   ([`DIAL_FACE_ID`]) in the registry.
//! - **`listen` (accept, peer)** — pico forces PEER mode, does a non-blocking
//!   `bind()` + `listen()`, spawns an async accept task, and **returns
//!   immediately with zero peers and no error** (`src/net/session.c:87-118`,
//!   `src/transport/manager.c:98-130`); the LISTEN branch runs no handshake at
//!   all (`transport.c:294-311`). So `z_open` here returns as soon as the bind
//!   succeeds, and peers are accepted in the background.
//!
//! Round 1 blocked the `listen` role until its first peer connected, which was
//! both a divergence and an uncancellable hang (no `SessionState` existed yet,
//! so `z_close` could not interrupt it). R2 removes it: the bind is the whole
//! of `z_open(listen)`, and the accept loop races a cancellable shutdown.

use std::ffi::c_void;

use crate::abi::{z_moved_config_t, z_owned_config_t};
use crate::config::{
    ConfigState, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY,
    Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY, Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_NULL, Z_OK};
use wz_capi_core::drive::{open_blocking, OpenError, SessionState};
use wz_runtime_tokio::session_glue::WhatAmI;

// --- ABI structs (session owned = pico rc `{ void* _val; void* _cnt }`) ----

/// Owned session (pico `z_owned_session_t`, 16 B rc). `_val` carries our
/// `Box<SessionState>` handle; `_cnt` is unused.
#[repr(C)]
pub struct z_owned_session_t {
    pub(crate) _val: *mut c_void,
    pub(crate) _cnt: *mut c_void,
}

/// Loaned session (pico `z_loaned_session_t`), same 16 B layout.
#[repr(C)]
pub struct z_loaned_session_t {
    pub(crate) _val: *mut c_void,
    pub(crate) _cnt: *mut c_void,
}

/// Moved session (pico `z_moved_session_t`).
#[repr(C)]
pub struct z_moved_session_t {
    pub(crate) _this: z_owned_session_t,
}

impl z_owned_session_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            _val: std::ptr::null_mut(),
            _cnt: std::ptr::null_mut(),
        }
    }
}

/// Read the [`SessionState`] behind a loaned session, or `None` if the pointer
/// or its handle slot is null.
///
/// Lives here, beside BOTH types it touches ([`SessionState`] and
/// [`z_loaned_session_t`]), because every module that reaches a session needs
/// it: `pubsub` and `query` each carried a byte-identical private copy until
/// R311y294 folded them into this one.
///
/// # Safety
/// `zs` must be null, or a valid `z_loaned_session_t` whose `_val` slot is a
/// live `Box::into_raw::<SessionState>` pointer (what [`z_open`] installs).
pub unsafe fn session_state<'a>(zs: *const z_loaned_session_t) -> Option<&'a SessionState> {
    if zs.is_null() {
        return None;
    }
    let val = (*zs)._val;
    if val.is_null() {
        return None;
    }
    Some(&*(val as *const SessionState))
}

// --- z_open / z_close ------------------------------------------------------

/// Open a session, consuming the moved config (pico `z_open`). A `connect`
/// config blocks until Established; a `listen` config returns as soon as the
/// bind succeeds. The `options` pointer is accepted for ABI compatibility and
/// ignored.
#[no_mangle]
pub unsafe extern "C" fn z_open(
    zs: *mut z_owned_session_t,
    config: *mut z_moved_config_t,
    _options: *const c_void,
) -> ZResult {
    guarded(|| {
        if zs.is_null() || config.is_null() {
            return Z_ERR_NULL;
        }
        // Always-initialize the out-param (pico contract) before any fallible
        // work, so a caller reading `*zs` on an error path sees a null session.
        *zs = z_owned_session_t::null_value();
        let cfg_handle = (*config)._this.handle;
        if cfg_handle.is_null() {
            return Z_ERR_NULL;
        }
        // z_open consumes the config: take ownership and null the source so a
        // defensive later `z_config_drop` is a safe no-op.
        let cfg = Box::from_raw(cfg_handle as *mut ConfigState);
        (*config)._this = z_owned_config_t::null_value();

        let connect = cfg.get(Z_CONFIG_CONNECT_KEY).map(str::to_owned);
        let listen = cfg.get(Z_CONFIG_LISTEN_KEY).map(str::to_owned);
        // R311y406 — the LISTEN server cert (cert-chain + private-key PEM FILE PATHS) a
        // cert-bearing listener presents, from zenoh-pico's native listen-cert config
        // keys (the tls-block keys zenoh reuses for quic). pico wires them into the QUIC
        // acceptor (`transport-link-quic`, no tls acceptor). `None` (cert-free
        // tcp/ws/udp listen) keeps the default bind.
        let listen_cert = cfg
            .get(Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY)
            .map(str::to_owned);
        let listen_key = cfg
            .get(Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY)
            .map(str::to_owned);
        // The dial role's whatami is config-driven, mirroring pico's
        // `_z_config_get_mode` (`~/zenoh-pico/src/net/session.c:120-140`,
        // default CLIENT): `mode=peer` opens a dialing PEER, otherwise CLIENT.
        // (The listen role forces PEER regardless — pico force-inserts
        // `MODE=PEER` for any listen config, session.c:98.)
        let dial_whatami = match cfg.get(Z_CONFIG_MODE_KEY) {
            Some("peer") => WhatAmI::Peer,
            _ => WhatAmI::Client,
        };
        drop(cfg);

        if connect.is_none() && listen.is_none() {
            return crate::result::Z_ERR_INVALID;
        }
        // A config carrying BOTH connect and listen is pico's dual-role
        // listen-and-dial peer (`session.c:99-108` appends the connect
        // endpoints after forcing the listen endpoint to PEER mode). That
        // hybrid — an N-face accept listener AND a dial face on one runtime —
        // is a follow-up; reject it explicitly rather than SILENTLY dropping
        // the listener (which is what picking one arm would do).
        if connect.is_some() && listen.is_some() {
            return crate::result::Z_ERR_INVALID;
        }

        match open_blocking(connect, listen, listen_cert, listen_key, dial_whatami) {
            Ok(state) => {
                *zs = z_owned_session_t {
                    _val: Box::into_raw(Box::new(state)) as *mut c_void,
                    _cnt: std::ptr::null_mut(),
                };
                Z_OK
            }
            // R311y498 — the core reports a NEUTRAL failure; this shim maps it
            // onto zenoh-pico's code. The mapping exists precisely because the
            // other ABI's `int8_t` uses different values for the same idea.
            Err(OpenError::DriveFailed) => Z_ERR_GENERIC,
        }
    })
}

/// Close a session (pico `z_close`): stop the drive loop and join the driver
/// thread. Does not free the owned struct — that is `z_session_drop`.
#[no_mangle]
pub unsafe extern "C" fn z_close(zs: *mut z_loaned_session_t, _options: *const c_void) -> ZResult {
    guarded(|| {
        if zs.is_null() || (*zs)._val.is_null() {
            return Z_ERR_NULL;
        }
        let state = &*((*zs)._val as *const SessionState);
        state.close();
        Z_OK
    })
}

// --- session ownership family (null/check/loan/loan_mut/move/take/drop) -----

/// Zero an owned session (pico `z_internal_session_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_session_null(obj: *mut z_owned_session_t) {
    if !obj.is_null() {
        *obj = z_owned_session_t::null_value();
    }
}

/// `true` iff the owned session holds a live handle (pico
/// `z_internal_session_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_session_check(obj: *const z_owned_session_t) -> bool {
    guard_val(false, || !obj.is_null() && !(*obj)._val.is_null())
}

/// Borrow a session immutably (pico `z_session_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_session_loan(
    obj: *const z_owned_session_t,
) -> *const z_loaned_session_t {
    obj as *const z_loaned_session_t
}

/// Borrow a session mutably (pico `z_session_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_session_loan_mut(
    obj: *mut z_owned_session_t,
) -> *mut z_loaned_session_t {
    obj as *mut z_loaned_session_t
}

/// Move-cast a session (pico `z_session_move`).
#[no_mangle]
pub unsafe extern "C" fn z_session_move(obj: *mut z_owned_session_t) -> *mut z_moved_session_t {
    obj as *mut z_moved_session_t
}

/// Take a session out of `src` into `dst` (pico `z_session_take`).
#[no_mangle]
pub unsafe extern "C" fn z_session_take(dst: *mut z_owned_session_t, src: *mut z_moved_session_t) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst)._val = (*src)._this._val;
    (*dst)._cnt = (*src)._this._cnt;
    (*src)._this = z_owned_session_t::null_value();
}

/// Drop an owned session (pico `z_session_drop`): closes (if not already) and
/// frees the [`SessionState`].
#[no_mangle]
pub unsafe extern "C" fn z_session_drop(obj: *mut z_moved_session_t) {
    let _ = guarded(|| {
        if obj.is_null() {
            return Z_OK;
        }
        let val = (*obj)._this._val;
        if !val.is_null() {
            // SessionState::drop runs close() (idempotent).
            drop(Box::from_raw(val as *mut SessionState));
            (*obj)._this = z_owned_session_t::null_value();
        }
        Z_OK
    });
}

// --- zp_*_task shims -------------------------------------------------------
//
// wz's drive loop already performs the read + lease/keepalive work these pico
// tasks start, so the exports are Z_OK shims. They are REQUIRED: a real pico
// program calls them after `z_open`, and a missing symbol would fail to link.
// This also matches pico 1.9.0, where the background executor is started inside
// `z_open` by default and these are legacy: `zp_start_read_task` re-starts the
// already-running executor and `zp_start_lease_task` is itself a literal no-op
// (`~/zenoh-pico/src/api/api.c:2491-2509`; the options are documented
// "Deprecated ... started automatically when session is created",
// `include/zenoh-pico/api/types.h:179-184`).

/// pico `zp_start_read_task` — no-op (the drive loop already reads).
#[no_mangle]
pub unsafe extern "C" fn zp_start_read_task(
    _zs: *mut z_loaned_session_t,
    _options: *const c_void,
) -> ZResult {
    Z_OK
}

/// pico `zp_stop_read_task` — no-op.
#[no_mangle]
pub unsafe extern "C" fn zp_stop_read_task(_zs: *mut z_loaned_session_t) -> ZResult {
    Z_OK
}

/// pico `zp_start_lease_task` — no-op (the drive loop already leases).
#[no_mangle]
pub unsafe extern "C" fn zp_start_lease_task(
    _zs: *mut z_loaned_session_t,
    _options: *const c_void,
) -> ZResult {
    Z_OK
}

/// pico `zp_stop_lease_task` — no-op.
#[no_mangle]
pub unsafe extern "C" fn zp_stop_lease_task(_zs: *mut z_loaned_session_t) -> ZResult {
    Z_OK
}

/// pico `zp_spin_once` — no-op (the drive loop IS the executor this pumps).
///
/// This is the export the SINGLE-THREADED example pair is built around.
/// `z_pub_st.c` / `z_sub_st.c` compile only under `Z_FEATURE_MULTI_THREAD == 0`,
/// where pico has no background executor thread and the application is
/// responsible for advancing the session by hand: each loop iteration sleeps and
/// then calls this to run ONE pending task (read, lease, keep-alive, accept,
/// connect) off pico's task queue
/// (`vendor/zenoh-pico/include/zenoh-pico/api/primitives.h:3336-3345`).
///
/// wz has no such queue to drain. Its session SELF-DRIVES — the face's drive
/// loop performs the read / lease / keep-alive work on its own runtime whether
/// or not the C thread ever calls in — so the faithful shim is to return
/// immediately, exactly as the `zp_start_read_task` / `zp_start_lease_task`
/// family above already does for the multi-threaded build.
///
/// The divergence is deliberate and one-directional: wz makes progress the
/// caller did not ask for, never less. A program written against the
/// single-threaded contract therefore behaves as its author intended (its
/// samples flow, its lease is held), while one that never called this would ALSO
/// work here — which is the honest statement of what wz's runtime model gives
/// up, not a claim that the call is meaningless.
///
/// `void` return: pico reports no status here, so a null or dead session cannot
/// be signalled to the caller. The state lookup is still performed so the
/// argument is dereferenced under [`guarded`] rather than by the C caller's next
/// unrelated call.
#[no_mangle]
pub unsafe extern "C" fn zp_spin_once(zs: *const z_loaned_session_t) {
    let _ = guarded(|| {
        let _ = session_state(zs);
        Z_OK
    });
}

// --- TX batching (pico `zp_batch_*`) ---------------------------------------

/// Open a TX batching window (pico `zp_batch_start`).
///
/// pico drives ONE transport, so its batch control is a single call
/// (`src/api/api.c:2444-2450` into `_z_transport_start_batching`). wz holds N
/// faces, so the window opens on each — the same fan-out every other
/// session-level export here performs. Upstream's `z_pub_thr.c` brackets its
/// publish loop with `zp_batch_start` / `zp_batch_stop`, which is what makes it
/// a THROUGHPUT benchmark rather than a publish loop.
#[no_mangle]
pub unsafe extern "C" fn zp_batch_start(zs: *const z_loaned_session_t) -> ZResult {
    guarded(|| match session_state(zs) {
        Some(state) => {
            state.shared.batch_start_all();
            Z_OK
        }
        None => Z_ERR_NULL,
    })
}

/// Flush every open batch window without closing it (pico `zp_batch_flush`).
///
/// Shipped alongside its two siblings even though no upstream example calls it:
/// an asymmetric family fails to link for the NEXT program rather than this one,
/// which is the lesson this crate already paid for once with
/// `z_put_options_default`.
#[no_mangle]
pub unsafe extern "C" fn zp_batch_flush(zs: *const z_loaned_session_t) -> ZResult {
    guarded(|| match session_state(zs) {
        Some(state) => {
            state.shared.batch_flush_all();
            Z_OK
        }
        None => Z_ERR_NULL,
    })
}

/// Close every batch window, draining what it holds (pico `zp_batch_stop`).
#[no_mangle]
pub unsafe extern "C" fn zp_batch_stop(zs: *const z_loaned_session_t) -> ZResult {
    guarded(|| match session_state(zs) {
        Some(state) => {
            state.shared.batch_stop_all();
            Z_OK
        }
        None => Z_ERR_NULL,
    })
}

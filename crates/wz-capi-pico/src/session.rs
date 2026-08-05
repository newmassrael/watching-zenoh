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
use crate::config::{ConfigState, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY};
// The twelve TLS key constants are consumed ONLY by `resolve_tls_config`, which
// exists only when a certificate has a backend that could consume it. Importing
// them at module scope would make the no-backend build carry twelve unused
// imports, which `-D warnings` rejects — so the import rides the same cfg as its
// single consumer rather than the consumer being widened to justify the import.
#[cfg(any(feature = "transport-link-tls", feature = "transport-link-quic"))]
use crate::config::{
    Z_CONFIG_TLS_CONNECT_CERTIFICATE_BASE64_KEY, Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY,
    Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_BASE64_KEY, Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY,
    Z_CONFIG_TLS_ENABLE_MTLS_KEY, Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY,
    Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY, Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY,
    Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY, Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY,
    Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY, Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_NULL, Z_OK};
use wz_capi_core::drive::{open_blocking, CapiTlsConfig, OpenError, SessionState};
use wz_runtime_tokio::session_glue::WhatAmI;

/// Resolve one certificate value from its PATH key or its `*_BASE64` inline key.
///
/// pico offers both forms for every TLS certificate value and they mean the same
/// thing, so this collapses them at the boundary: the path is read off disk, the
/// inline blob is base64-decoded, and both yield PEM bytes.
///
/// PATH WINS when both are set, matching the examples' own precedence — each of
/// them inserts the inline blob only in the `else` arm of "did the user pass a
/// path" (`z_pub_tls.c:150-176`). Encoding the same precedence here means a
/// caller that sets both by hand gets the answer the example would have given.
///
/// A value that is present but unreadable or undecodable is an ERROR, never a
/// silent `None`: `None` means "the caller configured no such material", and
/// letting a corrupt one collapse into it would open a session with less
/// protection than was asked for.
#[cfg(any(feature = "transport-link-tls", feature = "transport-link-quic"))]
fn resolve_pem(
    cfg: &ConfigState,
    path_key: u8,
    base64_key: u8,
) -> Result<Option<Vec<u8>>, ZResult> {
    if let Some(path) = cfg.get(path_key) {
        return wz_runtime_tokio::tls_config::read_pem_file(path)
            .map(Some)
            .map_err(|_| crate::result::Z_ERR_INVALID);
    }
    if let Some(b64) = cfg.get(base64_key) {
        return wz_runtime_tokio::tls_config::decode_base64_pem(b64)
            .map(Some)
            .map_err(|_| crate::result::Z_ERR_INVALID);
    }
    Ok(None)
}

/// Read pico's twelve TLS config keys into the ABI-neutral [`CapiTlsConfig`].
///
/// The boolean keys are compared against `"true"` because that is the literal
/// the examples insert (`z_pub_tls.c:225` writes `"true"` / `"false"`), and
/// anything else — including an absent key — is pico's `false` default.
///
/// Gated on the two link features because the PEM loaders it calls are: wz's
/// `tls_config` module is itself `cfg(any(transport-link-tls,
/// transport-link-quic))`, since without either backend there is nothing that
/// could consume a certificate. The `not` arm below is not a stub — it is the
/// correct answer for that build, where a `tls/` or `quic/` endpoint is rejected
/// at bind/dial as `Unsupported` and the cert keys have no consumer to reach.
#[cfg(any(feature = "transport-link-tls", feature = "transport-link-quic"))]
fn resolve_tls_config(cfg: &ConfigState) -> Result<CapiTlsConfig, ZResult> {
    let enable_mtls = cfg.get(Z_CONFIG_TLS_ENABLE_MTLS_KEY) == Some("true");
    // The mTLS material is read only when mTLS is ON. pico gates its own
    // insertion the same way (`if (enable_mtls)`), so reading it unconditionally
    // would make wz present a client cert in a configuration where pico does not.
    let (connect_cert_pem, connect_key_pem) = if enable_mtls {
        (
            resolve_pem(
                cfg,
                Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY,
                Z_CONFIG_TLS_CONNECT_CERTIFICATE_BASE64_KEY,
            )?,
            resolve_pem(
                cfg,
                Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY,
                Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_BASE64_KEY,
            )?,
        )
    } else {
        (None, None)
    };
    Ok(CapiTlsConfig {
        root_ca_pem: resolve_pem(
            cfg,
            Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY,
            Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY,
        )?,
        verify_name_on_connect: cfg.get(Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY) == Some("true"),
        connect_cert_pem,
        connect_key_pem,
        listen_cert_pem: resolve_pem(
            cfg,
            Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY,
            Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY,
        )?,
        listen_key_pem: resolve_pem(
            cfg,
            Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY,
            Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY,
        )?,
        require_client_auth: enable_mtls,
    })
}

/// The no-TLS-backend build: no certificate can reach a consumer, so the
/// cert-free config is the honest resolution. The keys still PARSE into the
/// config map (`zp_config_insert` is scheme-agnostic), which is what keeps a
/// program written against the full key set compiling and running here — it just
/// cannot open a `tls/` endpoint, and the runtime says so at bind/dial.
#[cfg(not(any(feature = "transport-link-tls", feature = "transport-link-quic")))]
fn resolve_tls_config(_cfg: &ConfigState) -> Result<CapiTlsConfig, ZResult> {
    Ok(CapiTlsConfig::default())
}

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
        // R311y406 / R311y534 — the TLS material, RESOLVED here (path or inline
        // base64 -> PEM bytes) because the key numbers are this ABI's knowledge.
        // A malformed value fails the open rather than degrading to a plaintext
        // or trust-free session: a caller that asked for TLS and silently got
        // something else is the one outcome worse than a failed z_open.
        let tls = match resolve_tls_config(&cfg) {
            Ok(tls) => tls,
            Err(code) => return code,
        };
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

        match open_blocking(connect, listen, tls, dial_whatami) {
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

// --- R311y559: the entity-identity accessors --------------------------------
//
// Every zenoh entity a program declares has a GLOBAL id — the session's zid
// paired with a session-scope entity id — and upstream exports one accessor per
// entity kind. The census found the whole family missing, which is why they
// live together here rather than beside each handle type: they are one claim
// with five spellings, and splitting them across five modules is how the
// `zid` half ends up read from a different place in each.

/// The global id of an entity declared on `zs`, or the empty id when the
/// session is gone.
///
/// The `zid` half always comes from the SESSION, never from the handle: an
/// entity's identity is `(this session's zid, this entity's eid)`, and reading
/// the zid per-handle would be a second source for a fact that has one.
pub(crate) unsafe fn entity_global_id(
    zs: &SessionState,
    eid: u64,
) -> crate::advanced::z_entity_global_id_t {
    crate::advanced::z_entity_global_id_t {
        zid: crate::zid::z_id_t { id: zs.zid() },
        // TRUNCATING, and that is upstream's width rather than a loss: zenoh's
        // `_z_entity_global_id_t.eid` is a `uint32_t`, so the wire cannot carry
        // more. A session declaring 2^32 entities would wrap, which is the same
        // thing upstream does.
        eid: eid as u32,
    }
}

/// The session's own global id (pico `z_session_id`) — its zid with entity id
/// 0, which is what upstream reports for the session entity itself.
///
/// # Safety
/// `zs` must be null or a live loaned session.
#[no_mangle]
pub unsafe extern "C" fn z_session_id(
    zs: *const z_loaned_session_t,
) -> crate::advanced::z_entity_global_id_t {
    crate::ffi::guard_val(
        crate::advanced::z_entity_global_id_t {
            zid: crate::zid::z_id_t::empty(),
            eid: 0,
        },
        || match session_state(zs) {
            Some(state) => entity_global_id(state, 0),
            None => crate::advanced::z_entity_global_id_t {
                zid: crate::zid::z_id_t::empty(),
                eid: 0,
            },
        },
    )
}

/// Whether the session has been closed (pico `z_session_is_closed`).
///
/// A NULL / spent handle reports CLOSED. That is the safe direction and it is
/// also the truthful one: a program holding a session it has already dropped
/// has no open session, and reporting "open" would invite it to publish
/// through a dead handle.
///
/// # Safety
/// `zs` must be null or a live loaned session.
#[no_mangle]
pub unsafe extern "C" fn z_session_is_closed(zs: *const z_loaned_session_t) -> bool {
    crate::ffi::guard_val(true, || match session_state(zs) {
        Some(state) => state.is_closed(),
        None => true,
    })
}

/// Borrow a publisher's keyexpr (pico `z_publisher_keyexpr`).
///
/// # Safety
/// `publisher` must be null or a live loaned publisher.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_keyexpr(
    publisher: *const crate::pubsub::z_loaned_publisher_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    crate::ffi::guard_val(std::ptr::null(), || {
        match crate::abi::handle_ref::<
            crate::pubsub::z_loaned_publisher_t,
            crate::pubsub::PublisherState,
        >(publisher)
        {
            Some(state) => state.loaned_keyexpr(),
            None => std::ptr::null(),
        }
    })
}

/// A publisher's global entity id (pico `z_publisher_id`).
///
/// # Safety
/// `publisher` must be null or a live loaned publisher.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_id(
    publisher: *const crate::pubsub::z_loaned_publisher_t,
) -> crate::advanced::z_entity_global_id_t {
    entity_id_of(
        crate::abi::handle_ref::<
            crate::pubsub::z_loaned_publisher_t,
            crate::pubsub::PublisherState,
        >(publisher)
        .map(|s| (s.shared_zid(), s.entity_id())),
    )
}

/// Borrow a querier's keyexpr (pico `z_querier_keyexpr`).
///
/// # Safety
/// `querier` must be null or a live loaned querier.
#[no_mangle]
pub unsafe extern "C" fn z_querier_keyexpr(
    querier: *const crate::querier::z_loaned_querier_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    crate::ffi::guard_val(std::ptr::null(), || {
        match crate::abi::handle_ref::<
            crate::querier::z_loaned_querier_t,
            crate::querier::QuerierState,
        >(querier)
        {
            Some(state) => state.loaned_keyexpr(),
            None => std::ptr::null(),
        }
    })
}

/// A querier's global entity id (pico `z_querier_id`).
///
/// # Safety
/// `querier` must be null or a live loaned querier.
#[no_mangle]
pub unsafe extern "C" fn z_querier_id(
    querier: *const crate::querier::z_loaned_querier_t,
) -> crate::advanced::z_entity_global_id_t {
    entity_id_of(
        crate::abi::handle_ref::<crate::querier::z_loaned_querier_t, crate::querier::QuerierState>(
            querier,
        )
        .map(|s| (s.shared_zid(), s.entity_id())),
    )
}

/// Borrow a subscriber's keyexpr (pico `z_subscriber_keyexpr`).
///
/// # Safety
/// `subscriber` must be null or a live loaned subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_keyexpr(
    subscriber: *const crate::pubsub::z_loaned_subscriber_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    crate::ffi::guard_val(std::ptr::null(), || {
        match crate::abi::handle_ref::<
            crate::pubsub::z_loaned_subscriber_t,
            crate::pubsub::SubscriberState,
        >(subscriber)
        {
            Some(state) => &state.loaned_keyexpr as *const crate::abi::z_loaned_keyexpr_t,
            None => std::ptr::null(),
        }
    })
}

/// A subscriber's global entity id (pico `z_subscriber_id`).
///
/// The `eid` is the registry's own `SubId` rather than a fresh allocation:
/// subscriptions already have a session-scope id, and minting a second one
/// would leave the handle and the registry naming the same entity differently.
///
/// # Safety
/// `subscriber` must be null or a live loaned subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_id(
    subscriber: *const crate::pubsub::z_loaned_subscriber_t,
) -> crate::advanced::z_entity_global_id_t {
    entity_id_of(
        crate::abi::handle_ref::<
            crate::pubsub::z_loaned_subscriber_t,
            crate::pubsub::SubscriberState,
        >(subscriber)
        .map(|s| (s.shared.zid(), s.id)),
    )
}

/// A queryable's global entity id (pico `z_queryable_id`).
///
/// # Safety
/// `queryable` must be null or a live loaned queryable.
#[no_mangle]
pub unsafe extern "C" fn z_queryable_id(
    queryable: *const crate::query::z_loaned_queryable_t,
) -> crate::advanced::z_entity_global_id_t {
    entity_id_of(crate::query::queryable_identity(queryable))
}

/// An advanced publisher's global entity id (pico `ze_advanced_publisher_id`).
///
/// # Safety
/// `pub_` must be null or a live loaned advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_id(
    pub_: *const crate::advanced::ze_loaned_advanced_publisher_t,
) -> crate::advanced::z_entity_global_id_t {
    entity_id_of(crate::advanced::advanced_publisher_identity(pub_))
}

/// Borrow an advanced publisher's keyexpr (pico
/// `ze_advanced_publisher_keyexpr`).
///
/// # Safety
/// `pub_` must be null or a live loaned advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_keyexpr(
    pub_: *const crate::advanced::ze_loaned_advanced_publisher_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    crate::advanced::advanced_publisher_keyexpr(pub_)
}

/// An advanced subscriber's global entity id (pico
/// `ze_advanced_subscriber_id`).
///
/// # Safety
/// `sub` must be null or a live loaned advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_id(
    sub: *const crate::advanced::ze_loaned_advanced_subscriber_t,
) -> crate::advanced::z_entity_global_id_t {
    entity_id_of(crate::advanced::advanced_subscriber_identity(sub))
}

/// Borrow an advanced subscriber's keyexpr (pico
/// `ze_advanced_subscriber_keyexpr`).
///
/// # Safety
/// `sub` must be null or a live loaned advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_keyexpr(
    sub: *const crate::advanced::ze_loaned_advanced_subscriber_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    crate::advanced::advanced_subscriber_keyexpr(sub)
}

/// Project an optional `(zid, eid)` into the ABI's global id, with the empty id
/// standing for a null / spent handle.
///
/// One projection for all seven accessors above so the "what does a dead handle
/// report" answer cannot differ between them — the class of asymmetry this
/// crate has already paid for.
fn entity_id_of(identity: Option<([u8; 16], u64)>) -> crate::advanced::z_entity_global_id_t {
    match identity {
        Some((zid, eid)) => crate::advanced::z_entity_global_id_t {
            zid: crate::zid::z_id_t { id: zid },
            eid: eid as u32,
        },
        None => crate::advanced::z_entity_global_id_t {
            zid: crate::zid::z_id_t::empty(),
            eid: 0,
        },
    }
}

// --- R311y559: the remaining option defaults + the two `zp_` task probes -----

/// pico `z_subscriber_options_t` — a ONE-BYTE dummy in this build.
///
/// The struct is `{ z_locality_t allowed_origin; }` under
/// `Z_FEATURE_LOCAL_SUBSCRIBER` and `{ uint8_t __dummy; }` without it, and the
/// generated `config.h` these programs compile against has the feature OFF. So
/// the field a caller can set does not exist, which is the same fact
/// `crate::pubsub`'s `Locality::Remote` subscribe pin records from the other
/// side. 1 B MEASURED.
#[repr(C)]
pub struct z_subscriber_options_t {
    pub __dummy: u8,
}

/// pico `z_open_options_t`, 16 B measured:
/// `{ bool auto_start_read_task; bool auto_start_lease_task; z_task_attr_t* }`.
///
/// Both booleans are DEPRECATED upstream — with multi-threading enabled the
/// tasks start automatically — and wz's session starts its own drive thread in
/// `z_open`, so they are accepted and have no effect here either. That is not a
/// wz divergence: it is upstream's own documented state for this build.
#[repr(C)]
pub struct z_open_options_t {
    pub auto_start_read_task: bool,
    pub auto_start_lease_task: bool,
    pub executor_task_attributes: *mut crate::sync::z_task_attr_t,
}

/// pico `z_close_options_t` — a one-byte dummy, 1 B measured.
#[repr(C)]
pub struct z_close_options_t {
    pub __dummy: u8,
}

/// pico `zp_task_read_options_t`, 8 B measured.
#[repr(C)]
pub struct zp_task_read_options_t {
    pub task_attributes: *mut crate::sync::z_task_attr_t,
}

/// pico `zp_task_lease_options_t`, 8 B measured.
#[repr(C)]
pub struct zp_task_lease_options_t {
    pub task_attributes: *mut crate::sync::z_task_attr_t,
}

const _: () = {
    assert!(std::mem::size_of::<z_subscriber_options_t>() == 1);
    assert!(std::mem::size_of::<z_open_options_t>() == 16);
    assert!(std::mem::size_of::<z_close_options_t>() == 1);
    assert!(std::mem::size_of::<zp_task_read_options_t>() == 8);
    assert!(std::mem::size_of::<zp_task_lease_options_t>() == 8);
};

/// Fill default subscriber options (pico `z_subscriber_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_options_default(options: *mut z_subscriber_options_t) {
    if !options.is_null() {
        (*options).__dummy = 0;
    }
}

/// Fill default open options (pico `z_open_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_open_options_default(options: *mut z_open_options_t) {
    if !options.is_null() {
        *options = z_open_options_t {
            auto_start_read_task: true,
            auto_start_lease_task: true,
            executor_task_attributes: std::ptr::null_mut(),
        };
    }
}

/// Fill default close options (pico `z_close_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_close_options_default(options: *mut z_close_options_t) {
    if !options.is_null() {
        (*options).__dummy = 0;
    }
}

/// Fill default read-task options (pico `zp_task_read_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zp_task_read_options_default(options: *mut zp_task_read_options_t) {
    if !options.is_null() {
        (*options).task_attributes = std::ptr::null_mut();
    }
}

/// Fill default lease-task options (pico `zp_task_lease_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zp_task_lease_options_default(options: *mut zp_task_lease_options_t) {
    if !options.is_null() {
        (*options).task_attributes = std::ptr::null_mut();
    }
}

/// Whether the session's READ task is running (pico `zp_read_task_is_running`).
///
/// wz runs ONE drive thread serving both roles rather than pico's separate read
/// and lease tasks, so this and [`zp_lease_task_is_running`] answer the same
/// question — "is the session still driving?" — and both are the negation of
/// [`z_session_is_closed`]. Stated rather than left to be inferred from two
/// identical bodies: a program polling one to decide whether the other is up
/// gets a consistent answer here, which is the property that matters.
///
/// # Safety
/// `zs` must be null or a live loaned session.
#[no_mangle]
pub unsafe extern "C" fn zp_read_task_is_running(zs: *const z_loaned_session_t) -> bool {
    !z_session_is_closed(zs)
}

/// Whether the session's LEASE task is running (pico
/// `zp_lease_task_is_running`). See [`zp_read_task_is_running`].
///
/// # Safety
/// `zs` must be null or a live loaned session.
#[no_mangle]
pub unsafe extern "C" fn zp_lease_task_is_running(zs: *const z_loaned_session_t) -> bool {
    !z_session_is_closed(zs)
}

/// pico's default priority (pico `z_priority_default`) — `Z_PRIORITY_DATA`.
#[no_mangle]
pub extern "C" fn z_priority_default() -> std::ffi::c_int {
    crate::query::Z_PRIORITY_DEFAULT
}

/// pico's default reliability (pico `z_reliability_default`) —
/// `Z_RELIABILITY_RELIABLE`, which is 0 on this ABI and 1 in wz's own enum.
#[no_mangle]
pub extern "C" fn z_reliability_default() -> std::ffi::c_int {
    crate::pubsub::Z_RELIABILITY_RELIABLE
}

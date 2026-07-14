// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_open` / `z_close`, the session ownership family, and the `zp_*_task`
//! shims — plus the async-drive bridge that makes a wz `Session` behave like a
//! self-driving pico session.
//!
//! ## The drive bridge (the crux)
//!
//! wz has no `Session::open` and no self-driving session: a subscriber
//! callback fires only while `drive_session_until_terminal`
//! (`wz-runtime-tokio/src/session_glue.rs:729`) actively pumps the link,
//! dispatching each `IterationEvent` into the SAME observer the subscriber
//! registered on. pico's `z_open`, by contrast, returns immediately and the
//! read/lease tasks run in the background.
//!
//! Round 1 bridges this by owning a shared multi-thread tokio runtime and
//! spawning one OS thread per session that `block_on`s the whole session
//! lifecycle: establish link → open handshake → hand a `Session` clone back
//! to the C caller → run the drive loop until `z_close` signals shutdown.
//! `block_on` does not require the driven future to be `Send`, so the drive
//! loop compiles regardless of the `Engine`/`InboundLink` auto-traits; only
//! the writer task (already spawned by the open path) needs `Send`, which it
//! has. The runtime is multi-thread so the socket writer task and the drive
//! loop make progress concurrently while the C thread is between calls.
//!
//! `z_open` blocks until the session reaches Established (both dial and
//! accept). An acceptor therefore blocks until its first peer connects;
//! a non-blocking listener that accepts in the background is a follow-up
//! refinement.

use std::ffi::c_void;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::thread::JoinHandle;

use tokio::sync::Notify;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::TokioSession;
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SessionTimeouts, SigningKey,
    WhatAmI,
};
use wz_runtime_tokio::session_open::{
    accept_and_open_session, accept_endpoint, dial_endpoint, initiate_and_open_session, DialConfig,
    OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex as WzMutex;

use crate::abi::{z_moved_config_t, z_owned_config_t};
use crate::config::{ConfigState, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_NULL, Z_OK};

// --- ABI structs (session owned = pico rc `{ void* _val; void* _cnt }`) ----

/// Owned session (pico `z_owned_session_t`, 16 B rc). `_val` carries our
/// `Box<SessionState>` handle; `_cnt` is unused in Round 1.
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

// --- per-session runtime + state -------------------------------------------

/// The C session handle: a `Session` clone for `z_put` / `z_declare_*` calls
/// made from the C thread, plus the drive thread's shutdown signal and join
/// handle.
pub(crate) struct SessionState {
    pub(crate) session: TokioSession,
    shutdown: Arc<Notify>,
    driver: StdMutex<Option<JoinHandle<()>>>,
}

impl SessionState {
    /// Signal the drive loop to stop and join the driver thread. Idempotent.
    fn close(&self) {
        self.shutdown.notify_waiters();
        if let Ok(mut guard) = self.driver.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.close();
    }
}

/// Round-1 fixed session-init parameters (mirrors the wz-ap-demo defaults).
/// `zid` is role-distinguished so a same-process dialer and acceptor never
/// collide; per-process entropy is a follow-up refinement.
fn init_params(whatami: WhatAmI, zid: Vec<u8>) -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami,
        zid,
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 65535,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        cookie_signing_key: SigningKey::new(vec![0xAB; 32])
            .expect("32-byte demo key satisfies the >= 32 invariant"),
    }
}

/// The drive-thread body: establish the link, run the open handshake, hand a
/// `Session` clone back through `tx`, then pump the session until `z_close`.
async fn drive_session(
    connect: Option<String>,
    listen: Option<String>,
    tx: mpsc::Sender<Option<TokioSession>>,
    shutdown: Arc<Notify>,
) {
    let is_dial = connect.is_some();
    let dialed = if let Some(endpoint) = &connect {
        dial_endpoint(endpoint, &DialConfig::default()).await
    } else if let Some(endpoint) = &listen {
        accept_endpoint(endpoint).await
    } else {
        let _ = tx.send(None);
        return;
    };
    let dialed = match dialed {
        Ok(link) => link,
        Err(_) => {
            let _ = tx.send(None);
            return;
        }
    };

    let session_clock = TokioTime::new();
    // Role from the config: a `connect` endpoint dials as Client, a `listen`
    // endpoint accepts as Peer (the pico z_open connect/listen split). Distinct
    // zids so a same-process dialer and acceptor never collide.
    let (whatami, zid) = if is_dial {
        (WhatAmI::Client, vec![0x01, 0x02, 0x03, 0x04])
    } else {
        (WhatAmI::Peer, vec![0x05, 0x06, 0x07, 0x08])
    };
    let params = init_params(whatami, zid);

    let opened = if is_dial {
        initiate_and_open_session(dialed, params, session_clock, None, DEFAULT_OPEN_TICK_MS).await
    } else {
        accept_and_open_session(dialed, params, session_clock, None, DEFAULT_OPEN_TICK_MS).await
    };
    let OpenedSession {
        mut engine,
        actions,
        inbound,
        writer_handle,
        ..
    } = match opened {
        Ok(opened) => opened,
        Err(_) => {
            let _ = tx.send(None);
            return;
        }
    };

    let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(actions.clone(), observer.clone(), Arc::new(session_clock));

    // Hand a clone to the C thread; if it hung up, abandon the open.
    if tx.send(Some(session.clone())).is_err() {
        return;
    }

    let mut driver = inbound;
    let timeouts = SessionTimeouts::spec_defaults();
    let session_for_dispatch = session;
    let mut dispatch = |event: IterationEvent<'_>| {
        session_for_dispatch.dispatch_iteration_event(event);
    };

    tokio::select! {
        _ = drive_session_until_terminal(
            &mut driver,
            &actions,
            &mut engine,
            None,
            &session_clock,
            &timeouts,
            &mut dispatch,
        ) => {}
        _ = shutdown.notified() => {}
    }

    drop(writer_handle);
}

/// Open a session synchronously, blocking the calling (C) thread until the
/// handshake reaches Established. Returns the C-side [`SessionState`].
fn open_blocking(connect: Option<String>, listen: Option<String>) -> Result<SessionState, ZResult> {
    let (tx, rx) = mpsc::channel::<Option<TokioSession>>();
    let shutdown = Arc::new(Notify::new());
    let shutdown_drive = shutdown.clone();

    // One dedicated multi-thread runtime PER session, owned by its driver
    // thread: the `block_on` future need not be `Send` (so the drive loop
    // compiles regardless of `Engine`/`InboundLink` auto-traits), while the
    // socket writer task (spawned during open) and the I/O reactor run on the
    // runtime's worker threads. Two workers suffice — the wz reference
    // two-session loopback test drives to Established with `worker_threads=2`.
    // A shared runtime driven by two `block_on`s starved the concurrent
    // handshake (the acceptor timed out into a pre-Established Terminal);
    // per-session isolation lets each session drive its own link to completion.
    let handle = std::thread::Builder::new()
        .name("wz-capi-pico-drive".to_owned())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("wz-capi-pico-rt")
                .build()
            {
                Ok(rt) => rt,
                Err(_) => {
                    let _ = tx.send(None);
                    return;
                }
            };
            rt.block_on(drive_session(connect, listen, tx, shutdown_drive));
            // `rt` is dropped here, after the drive loop has returned.
        })
        .map_err(|_| Z_ERR_GENERIC)?;

    match rx.recv() {
        Ok(Some(session)) => Ok(SessionState {
            session,
            shutdown,
            driver: StdMutex::new(Some(handle)),
        }),
        _ => {
            // Open failed (link/handshake error, or the drive thread returned
            // without a session). Join the finished thread and report.
            let _ = handle.join();
            Err(Z_ERR_GENERIC)
        }
    }
}

// --- z_open / z_close ------------------------------------------------------

/// Open a session, consuming the moved config (pico `z_open`). Blocks until
/// Established. The `options` pointer is accepted for ABI compatibility and
/// ignored in Round 1.
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
        let cfg_handle = (*config)._this.handle;
        if cfg_handle.is_null() {
            *zs = z_owned_session_t::null_value();
            return Z_ERR_NULL;
        }
        // z_open consumes the config: take ownership and null the source so a
        // defensive later `z_config_drop` is a safe no-op.
        let cfg = Box::from_raw(cfg_handle as *mut ConfigState);
        (*config)._this = z_owned_config_t::null_value();

        let connect = cfg.get(Z_CONFIG_CONNECT_KEY).map(str::to_owned);
        let listen = cfg.get(Z_CONFIG_LISTEN_KEY).map(str::to_owned);
        drop(cfg);

        if connect.is_none() && listen.is_none() {
            *zs = z_owned_session_t::null_value();
            return crate::result::Z_ERR_INVALID;
        }

        match open_blocking(connect, listen) {
            Ok(state) => {
                *zs = z_owned_session_t {
                    _val: Box::into_raw(Box::new(state)) as *mut c_void,
                    _cnt: std::ptr::null_mut(),
                };
                Z_OK
            }
            Err(code) => {
                *zs = z_owned_session_t::null_value();
                code
            }
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

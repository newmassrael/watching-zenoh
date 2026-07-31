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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::thread::JoinHandle;

use tokio::sync::Notify;

use wz_runtime_tokio::accept_loop::accept_loop;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal_with_extra_deadline, ExtraDeadline, IterationEvent,
    SessionInitParams, SessionTimeouts, SigningKey, WhatAmI,
};
use wz_runtime_tokio::session_open::{
    bind_endpoint_with_config, dial_endpoint, initiate_and_open_session, AcceptConfig, DialConfig,
    OpenedSession, DEFAULT_OPEN_TICK_MS,
};

use crate::abi::{z_moved_config_t, z_owned_config_t};
use crate::config::{
    ConfigState, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY,
    Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY, Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY,
};
use crate::faces::{CApiForwarder, SharedSession, DIAL_FACE_ID};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_NULL, Z_OK};

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

// --- per-session state -----------------------------------------------------

/// The C session handle: the face registry + subscription SSOT the C thread
/// declares and publishes through, plus the drive thread's shutdown signal and
/// join handle.
pub(crate) struct SessionState {
    pub(crate) shared: Arc<SharedSession>,
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
    driver: StdMutex<Option<JoinHandle<()>>>,
}

impl SessionState {
    /// Signal the drive loop to stop and join the driver thread. Idempotent.
    fn close(&self) {
        // The latch is set BEFORE the notify, and is what makes the close
        // race-free: a `Notify` permit is single-use, so the latch covers a
        // `z_close` landing before the shutdown future is ever polled, while
        // `notify_one` (which stores a permit when no waiter is parked yet)
        // covers one landing between that check and the await. `notify_waiters`
        // would instead DROP the wakeup and the join below would hang.
        self.stop.store(true, Ordering::SeqCst);
        self.shutdown.notify_one();
        if let Ok(mut guard) = self.driver.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
        // Drop every face, which ENDS every in-flight `z_get` — pico's
        // `_z_session_close` -> `_z_flush_pending_queries`
        // (`~/zenoh-pico/src/session/utils.c:194`). See
        // [`SharedSession::clear_faces`] for why this is load-bearing rather
        // than tidiness: without it a get outstanding at `z_close` never fires
        // its completion, and one issued after `z_close` hangs forever.
        //
        // Ordering is the whole safety argument: the driver thread is JOINED
        // above, so no drive-thread callback can race the C `drop(context)`
        // this runs. Idempotent — a second `close` (or the `Drop` impl) finds
        // the registry already empty.
        self.shared.clear_faces();
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.close();
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
pub(crate) unsafe fn session_state<'a>(zs: *const z_loaned_session_t) -> Option<&'a SessionState> {
    if zs.is_null() {
        return None;
    }
    let val = (*zs)._val;
    if val.is_null() {
        return None;
    }
    Some(&*(val as *const SessionState))
}

/// pico's `Z_ZID_LENGTH` (`~/zenoh-pico/include/zenoh-pico/config.h.in:184`;
/// `ZENOH_ID_SIZE` = 16, `protocol/core.h:59-62`).
const ZID_LENGTH: usize = 16;

/// A fresh session zid, mirroring pico's default.
///
/// pico generates one per session: `_z_session_get_zid` takes the zid from
/// `Z_CONFIG_SESSION_ZID_KEY` when the config carries one, and otherwise
/// generates a random `Z_ZID_LENGTH`-byte id
/// (`~/zenoh-pico/src/api/api.c:846-855`). Round 1 instead hard-coded one zid
/// per ROLE, so every dialer this library opened claimed the SAME identity —
/// tolerable while a session held exactly one peer, but wrong for a listener
/// meant to hold several DISTINCT ones, since zenoh identifies a peer by its
/// zid.
///
/// Scope of the fix, measured rather than assumed: with this crate's feature set
/// the collision is currently LATENT, not an observed break. `transport-multilink`
/// (whose `join_link` aggregates same-zid links onto one logical session) is not
/// in the default bundle, and `FaceForwarder::dedups_faces_by_zid` defaults to
/// false, so two same-zid dialers are today still held as two faces — the
/// multi-peer gate test passes either way. This is a fidelity fix that also
/// closes that latent hazard, not a repair of a reproduced failure.
///
/// Honouring the `Z_CONFIG_SESSION_ZID_KEY` override is follow-up surface; this
/// is pico's default path.
///
/// `None` on OS-entropy failure, which fails the open — the same choice
/// wz-runtime-tokio already makes for signing-key entropy (`OpenError::
/// AuthEntropy`, `session_open.rs:1241-1246`). Handing back a fixed id instead
/// would reintroduce exactly the peer-collision this exists to prevent.
fn fresh_zid() -> Option<Vec<u8>> {
    let mut zid = vec![0u8; ZID_LENGTH];
    getrandom::getrandom(&mut zid).ok()?;
    Some(zid)
}

/// Fixed session-init parameters (mirrors the wz-ap-demo defaults), with a
/// per-session [`fresh_zid`].
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

/// The shutdown signal both roles race their drive against. See
/// [`SessionState::close`] for why the latch and the notify are both needed.
async fn shutdown_future(shutdown: Arc<Notify>, stop: Arc<AtomicBool>) {
    if stop.load(Ordering::SeqCst) {
        return;
    }
    shutdown.notified().await;
}

/// The `connect` role: dial, run the outbound handshake, land the one peer in
/// the registry, then pump it until `z_close`. `tx` unblocks `z_open` only once
/// the handshake has settled — pico's blocking client open.
async fn drive_dial(
    endpoint: String,
    whatami: WhatAmI,
    shared: Arc<SharedSession>,
    tx: mpsc::Sender<bool>,
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
    clock: TokioTime,
) {
    let dialed = match dial_endpoint(&endpoint, &DialConfig::default()).await {
        Ok(link) => link,
        Err(_) => {
            let _ = tx.send(false);
            return;
        }
    };
    let zid = match fresh_zid() {
        Some(zid) => zid,
        None => {
            let _ = tx.send(false);
            return;
        }
    };
    let params = init_params(whatami, zid);
    let opened = initiate_and_open_session(dialed, params, clock, None, DEFAULT_OPEN_TICK_MS).await;
    let OpenedSession {
        mut engine,
        actions,
        inbound,
        writer_handle,
        ..
    } = match opened {
        Ok(opened) => opened,
        Err(_) => {
            let _ = tx.send(false);
            return;
        }
    };

    // A dialed session has exactly one peer, so it occupies the single
    // `DIAL_FACE_ID` slot; from here the C surface is role-agnostic (it fans
    // over whatever faces the registry holds).
    shared.face_up(DIAL_FACE_ID, &actions);
    if tx.send(true).is_err() {
        return;
    }

    let mut driver = inbound;
    let timeouts = SessionTimeouts::spec_defaults();
    let dispatch_shared = shared.clone();
    // The `IterationEvent<'_>` annotation is load-bearing: `drive_session_until_terminal`
    // needs a HIGHER-RANKED `FnMut(IterationEvent<'_>)`, and without it inference
    // pins the closure to one specific lifetime ("implementation of `FnMut` is not
    // general enough").
    let mut dispatch = |event: IterationEvent<'_>| dispatch_shared.dispatch(DIAL_FACE_ID, event);
    // R311y296 — the dial role does NOT go through `accept_loop`, so the
    // `FaceForwarder::next_extra_deadline_ms` hook that arms the accepted
    // faces' wakes cannot reach it; this closure is the dial role's equivalent,
    // passed straight to the drive. Both roles therefore sweep expired `z_get`s
    // on their own drive thread at the deadline rather than on the ~3333 ms
    // keepalive cadence — a `connect` session is the ordinary pico get client
    // (a `z_get` to a router), so leaving this path on the plain drive would
    // have made the sweep late exactly where it matters most.
    let deadline_shared = shared.clone();
    let next_deadline = move || deadline_shared.next_reply_deadline_ms(DIAL_FACE_ID);
    // `face_up` above registered the face, so its re-arm signal exists.
    let revised = shared.deadline_revised(DIAL_FACE_ID);

    tokio::select! {
        _ = drive_session_until_terminal_with_extra_deadline(
            &mut driver,
            &actions,
            &mut engine,
            None,
            &clock,
            &timeouts,
            &mut dispatch,
            ExtraDeadline {
                next_ms: next_deadline,
                revised: revised.as_deref(),
            },
        ) => {}
        _ = shutdown_future(shutdown, stop) => {}
    }

    // `face_down` FIRST, and the ordering is load-bearing for LATENCY, not for
    // delivery — a distinction established by damaging it rather than by
    // reasoning about it. The registry's `FaceEntry` holds this session's
    // `TokioSession`, hence a clone of the `Arc<SessionLinkActions>` that owns
    // the outbound sender, and the drain below ends when that channel closes.
    // Move this line after the drain and every byte still arrives (the writer
    // drains the channel during the window either way; only its EXIT is missed),
    // so the delivery gate stays green — while every `z_close` silently pays the
    // full `WRITER_DRAIN_MS`: measured 51.5 ms against 0.1-0.5 ms.
    // `an_idle_z_close_does_not_burn_the_whole_drain_window` is what holds it.
    shared.face_down(DIAL_FACE_ID);
    // R311y486 — DRAIN, do not detach. `drop(writer_handle)` only detaches the
    // task, and `open_blocking`'s driver thread drops its per-session runtime on
    // the very next line, which aborts that task wherever it stands: with an
    // unbounded outbound channel and a peer that has stopped reading, "wherever
    // it stands" routinely means blocked mid-write with encoded frames still
    // queued, and every one of them is discarded after `z_put` already returned
    // `Z_OK`.
    //
    // The pico contract this restores is NOT that its `z_close` flushes — read
    // `_z_session_close` (`vendor/zenoh-pico/src/session/utils.c:167`) and it
    // stops the runtime and frees the resource / subscription / queryable /
    // pending-query registries; it moves no outbound byte. It does not have to:
    // pico's `z_put` writes on the CALLING thread all the way down
    // (`_z_write` -> `_z_send_n_msg` -> `_z_transport_tx_send_n_msg`,
    // `vendor/zenoh-pico/src/net/primitives.c:170`,
    // `vendor/zenoh-pico/src/transport/common/tx.c:487`), so when it returns the
    // bytes are already the kernel's and there is no queue left to lose. This
    // crate's `z_put` hands off to an async writer task instead — a queue pico
    // does not have, and therefore a teardown obligation pico does not have.
    // Draining it is what makes the two `z_put`s mean the same thing to a C
    // caller.
    //
    // Reconstructing the struct to reach `drain_to_close` is deliberate: the
    // drop order (engine before actions before the bounded await) is the whole
    // correctness argument, and R311y484 recorded it as the thing to COPY. A
    // hand-inlined copy here would be a second place for that order to rot, so
    // the dial role runs the library's own primitive — the same one
    // `accept_loop` drains every accepted face through, which is why the LISTEN
    // role never had this defect.
    OpenedSession {
        engine,
        actions,
        inbound: driver,
        writer_handle,
        clock,
    }
    .drain_to_close()
    .await;
}

/// R311y406 — build the LISTEN [`AcceptConfig`] from the native
/// `Z_CONFIG_TLS_LISTEN_{CERTIFICATE,PRIVATE_KEY}_KEY` PEM file paths (the peer of the
/// demo's `build_accept_config`). Both-or-neither. The key name mirrors zenoh-pico's
/// tls block, which zenoh reuses for quic; pico wires it into the QUIC acceptor slot
/// (pico has no `transport-link-tls` acceptor). Without `transport-link-quic` the
/// quic backend is not compiled, so a `quic/` listen surfaces `Unsupported` at bind
/// regardless — the paths are ignored and the cert-free default is returned.
#[cfg(feature = "transport-link-quic")]
fn listen_accept_config(cert: Option<&str>, key: Option<&str>) -> std::io::Result<AcceptConfig> {
    use wz_runtime_tokio::session_open::QuicAcceptConfig;
    use wz_runtime_tokio::tls_config::read_pem_file;
    match (cert, key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = read_pem_file(cert_path)?;
            let key_pem = read_pem_file(key_path)?;
            let quic = QuicAcceptConfig::from_cert_key_pem(&cert_pem, &key_pem)?;
            Ok(AcceptConfig::default().with_quic(quic))
        }
        (None, None) => Ok(AcceptConfig::default()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a quic/... listen needs BOTH the listen certificate and private-key config values",
        )),
    }
}

/// The `transport-link-quic`-less build: a `quic/...` listen surfaces the runtime's
/// typed `Unsupported` at bind, so the listen-cert config values are inert.
#[cfg(not(feature = "transport-link-quic"))]
fn listen_accept_config(cert: Option<&str>, key: Option<&str>) -> std::io::Result<AcceptConfig> {
    let _ = (cert, key);
    Ok(AcceptConfig::default())
}

/// The `listen` role: bind, unblock `z_open` immediately, then hold N
/// concurrent inbound peers until `z_close` — pico's non-blocking listener.
#[allow(clippy::too_many_arguments)]
async fn drive_listen(
    endpoint: String,
    listen_cert: Option<String>,
    listen_key: Option<String>,
    shared: Arc<SharedSession>,
    tx: mpsc::Sender<bool>,
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
    clock: TokioTime,
) {
    // Everything that can fail the open runs BEFORE the success signal below,
    // so a failure is reported to the C caller rather than silently killing a
    // listener it was told had opened.
    let zid = match fresh_zid() {
        Some(zid) => zid,
        None => {
            let _ = tx.send(false);
            return;
        }
    };
    // R311y406 — thread the LISTEN server cert (native Z_CONFIG_TLS_LISTEN_* keys)
    // into the bind's AcceptConfig, so a `z_open(listen="quic/..")` carrying the cert
    // presents it (was a cert-free `bind_endpoint` -> cert-absence reject). Building
    // the QuicAcceptConfig needs `transport-link-quic`; without that feature the quic
    // backend is not compiled, so a quic listen surfaces `Unsupported` at bind
    // regardless -- the cert paths are inert (see `listen_accept_config`).
    let accept_cfg = match listen_accept_config(listen_cert.as_deref(), listen_key.as_deref()) {
        Ok(cfg) => cfg,
        Err(_) => {
            let _ = tx.send(false);
            return;
        }
    };
    let listener = match bind_endpoint_with_config(&endpoint, &accept_cfg).await {
        Ok(listener) => listener,
        Err(_) => {
            let _ = tx.send(false);
            return;
        }
    };
    // CALLER fail-fast (mesh accept loop): pico's z_open(listen) holds N
    // concurrent inbound peers off ONE listener, so a NON-mesh-capable acceptor
    // (one that could not feed a multi-accept loop) is rejected here -- z_open
    // reports the open failure to the C caller (tx.send(false) -> Z_ERR_GENERIC),
    // the pico twin of run_router's bind-time guard and the BIND-time twin of the
    // accept loop's runtime `AcceptedLink::supports_mesh_multi_peer` backstop. Since
    // R311y404 every acceptor (quic incl., via its deferred-handshake split) is
    // mesh-capable, so this guard rejects no shipped transport; it stays defensive
    // for a future non-mesh acceptor.
    if !listener.supports_mesh_multi_peer() {
        let _ = tx.send(false);
        return;
    }
    // The bind is the WHOLE of pico's `z_open(listen)`: it binds + listens,
    // spawns an async accept task, and returns with zero peers and no error.
    // Unblocking here — before any peer exists — is the R2 fix; Round 1 awaited
    // the first peer instead, which was both a divergence and an uncancellable
    // hang. It also means the endpoint IS bound once `z_open` returns, so a
    // caller that dials it next cannot race the bind.
    if tx.send(true).is_err() {
        return;
    }

    // The accept loop holds every accepted peer as its own face and drives them
    // all on this one task; `CApiForwarder` lands each in the registry and
    // dispatches its inbound events into that face's own session. Shutdown is
    // a future the loop races, so a `z_close` with NO peer ever connected
    // unwinds a pending `accept()` cleanly.
    let forwarder = CApiForwarder::new(shared);
    let params = init_params(WhatAmI::Peer, zid);
    let _summary = accept_loop(
        listener,
        params,
        clock,
        DEFAULT_OPEN_TICK_MS,
        shutdown_future(shutdown, stop),
        |_event| {},
        &forwarder,
    )
    .await;
}

/// Open a session: spawn the drive thread and wait for the role's open
/// outcome. For `connect` that is the settled handshake; for `listen` it is
/// only the bind.
fn open_blocking(
    connect: Option<String>,
    listen: Option<String>,
    listen_cert: Option<String>,
    listen_key: Option<String>,
    dial_whatami: WhatAmI,
) -> Result<SessionState, ZResult> {
    let clock = TokioTime::new();
    let shared = Arc::new(SharedSession::new(clock));
    let shutdown = Arc::new(Notify::new());
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<bool>();

    let drive_shared = shared.clone();
    let drive_shutdown = shutdown.clone();
    let drive_stop = stop.clone();

    // One dedicated multi-thread runtime PER session, owned by its driver
    // thread: the `block_on` future need not be `Send` (the accept loop's
    // per-face drive futures are not), while the socket writer tasks and the
    // I/O reactor run on the runtime's worker threads. Two workers suffice —
    // the wz reference two-session loopback test drives to Established with
    // `worker_threads=2`. A shared runtime driven by two `block_on`s starved
    // the concurrent handshake (the acceptor timed out into a pre-Established
    // Terminal); per-session isolation lets each session drive its own links.
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
                    let _ = tx.send(false);
                    return;
                }
            };
            rt.block_on(async move {
                match (connect, listen) {
                    (Some(endpoint), _) => {
                        drive_dial(
                            endpoint,
                            dial_whatami,
                            drive_shared,
                            tx,
                            drive_shutdown,
                            drive_stop,
                            clock,
                        )
                        .await;
                    }
                    (None, Some(endpoint)) => {
                        drive_listen(
                            endpoint,
                            listen_cert,
                            listen_key,
                            drive_shared,
                            tx,
                            drive_shutdown,
                            drive_stop,
                            clock,
                        )
                        .await;
                    }
                    (None, None) => {
                        let _ = tx.send(false);
                    }
                }
            });
            // `rt` is dropped here, after the drive loop has returned.
        })
        .map_err(|_| Z_ERR_GENERIC)?;

    match rx.recv() {
        Ok(true) => Ok(SessionState {
            shared,
            shutdown,
            stop,
            driver: StdMutex::new(Some(handle)),
        }),
        _ => {
            // Open failed (bind / link / handshake error, or the drive thread
            // returned without opening). Join the finished thread and report.
            let _ = handle.join();
            Err(Z_ERR_GENERIC)
        }
    }
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
            Err(code) => code,
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

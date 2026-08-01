// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session LIFECYCLE half of the neutral model: per-session state, the
//! dedicated drive thread, and the dial / listen loops.
//!
//! Moved here verbatim from `wz-capi-pico::session` at R311y498 so a second C
//! ABI can sit on it. Only three things changed, and none of them is behaviour:
//! the visibility widened to `pub` (it now crosses a crate boundary), the thread
//! and runtime NAMES dropped their `-pico` (they are shared now), and the one
//! pico-typed edge — `open_blocking` returning `Result<_, ZResult>` with pico's
//! `Z_ERR_GENERIC` — became [`OpenError`], which each ABI maps onto its own
//! codes. zenoh-pico's `z_result_t` and zenoh-c's are both `int8_t`, but their
//! VALUES differ, so returning one ABI's constant from shared code would have
//! been a latent wrong-code bug the moment the second ABI arrived.

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

use crate::faces::{CApiForwarder, SharedSession, DIAL_FACE_ID};

/// Why [`open_blocking`] could not produce a live session.
///
/// Deliberately NOT a `z_result_t`: the two C ABIs wz exports both typedef that
/// to `int8_t` and then disagree about the VALUES, so shared code returning one
/// ABI's constant would be a wrong-code bug in the other. Each shim maps this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// The drive thread could not be spawned, its runtime could not be built,
    /// or the session did not reach Established.
    DriveFailed,
}

// --- per-session state -----------------------------------------------------

/// The C session handle: the face registry + subscription SSOT the C thread
/// declares and publishes through, plus the drive thread's shutdown signal and
/// join handle.
pub struct SessionState {
    pub shared: Arc<SharedSession>,
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
    driver: StdMutex<Option<JoinHandle<()>>>,
}

impl SessionState {
    /// Signal the drive loop to stop and join the driver thread. Idempotent.
    pub fn close(&self) {
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
pub fn open_blocking(
    connect: Option<String>,
    listen: Option<String>,
    listen_cert: Option<String>,
    listen_key: Option<String>,
    dial_whatami: WhatAmI,
) -> Result<SessionState, OpenError> {
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
        .name("wz-capi-drive".to_owned())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("wz-capi-rt")
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
        .map_err(|_| OpenError::DriveFailed)?;

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
            Err(OpenError::DriveFailed)
        }
    }
}

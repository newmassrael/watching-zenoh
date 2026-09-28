// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal_with_extra_deadline, EntropyUnavailable, ExtraDeadline,
    IterationEvent, OsEntropy, SessionInitParams, SessionTimeouts, SigningKey, TxQueueConf,
    WhatAmI,
};
use wz_runtime_tokio::session_open::{
    bind_endpoint_with_config, dial_endpoint, initiate_and_open_session, AcceptConfig, DialConfig,
    OpenedSession, OpenedSessionParts, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::startup_phase::{
    drive_connect_phase, drive_phase, endpoint_policy, endpoint_schedule, PhaseArm, PhaseBudget,
    PhasePolicy,
};

use crate::faces::{CApiForwarder, SharedSession, DIAL_FACE_ID};

/// How the dial half of an open treats an attempt that fails — zenoh's
/// `connect/timeout_ms` and `connect/exit_on_failure` ([`PhasePolicy`]) with the
/// `connect/retry` schedule that paces it ([`RetryPolicy`]), already resolved
/// for the role the session dials as.
///
/// ZA-3298. The two halves are the runtime's own types and the loop that runs
/// them is [`drive_connect_phase`], the runtime's transcription of upstream's
/// `connect_peers` fork (`zenoh/src/net/runtime/orchestrator.rs` @
/// `async fn connect_peers_single_link(&self, peers: &[EndPoints]) -> ZResult<()> {`).
/// Nothing here re-derives the arithmetic, so a C open cannot drift from the
/// router's connect phase.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DialPhase {
    /// `connect/timeout_ms` + `connect/exit_on_failure`.
    pub policy: PhasePolicy,
    /// `connect/retry`.
    pub schedule: RetryPolicy,
    /// R2948 — the schedule the session RE-DIALS on after an established link
    /// is lost, or `None` for a session that ends with its link. zenoh re-dials
    /// a closed session's configured endpoints
    /// (`zenoh/src/net/runtime/orchestrator.rs` @
    /// `.peers_connector_retry(peers, runtime.whatami() == WhatAmI::Client)`),
    /// and pico does too, by default (`Z_FEATURE_AUTO_RECONNECT`), on its own
    /// constant delay; each ABI names its own.
    pub redial: Option<RetryPolicy>,
    /// R2950 — how long a PEER's open waits for the endpoints it connects in
    /// the background before returning without them, or `None` for an open
    /// that does not wait: `scouting/delay` under
    /// `open/return_conditions/connect_scouted` (`zenoh/src/net/runtime/orchestrator.rs` @
    /// `&& tokio::time::timeout(delay, self.state.start_conditions.notified())`).
    pub start_window: Option<std::time::Duration>,
}

impl DialPhase {
    /// One attempt, and a failure fails the open: upstream's client column,
    /// and what every open here did before ZA-3298.
    pub const ONCE: Self = Self {
        policy: PhasePolicy::CONNECT_CLIENT_DEFAULT,
        schedule: RetryPolicy::ZENOH_DEFAULT,
        redial: None,
        start_window: None,
    };
}

/// Everything ONE dial attempt needs, owned, so a peer's per-endpoint faces
/// can each hold it on their own task.
struct Dialer {
    /// Each endpoint's dial config, built before any dial so a bad trust bundle
    /// fails the open rather than one attempt.
    dial_cfgs: Vec<(String, DialConfig)>,
    params: SessionInitParams,
    clock: TokioTime,
}

impl Dialer {
    /// Dial `endpoint` and run the outbound handshake: upstream's
    /// `open_transport_unicast`, which both connects and opens the session and
    /// is what `peers_connector_retry` re-attempts. A peer that is up but not
    /// yet serving therefore retries like one that is down.
    async fn open(&self, endpoint: &str) -> Result<OpenedSession, ()> {
        let dial_cfg = self
            .dial_cfgs
            .iter()
            .find(|(e, _)| e == endpoint)
            .map(|(_, cfg)| cfg)
            .ok_or(())?;
        let dialed = dial_endpoint(endpoint, dial_cfg).await.map_err(|_| ())?;
        initiate_and_open_session(
            dialed,
            self.params.clone(),
            self.clock,
            None,
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .map_err(|_| ())
    }
}

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
    /// This session's own zid, the 16 bytes it puts on the wire in its INIT.
    ///
    /// R311y528 — minted on the CALLING thread in [`open_blocking`] and handed
    /// to the drive thread, rather than minted inside the drive future. pico's
    /// `z_info_zid` must report the identity the peer actually sees
    /// (`~/zenoh-pico/src/api/api.c`, `_z_session_get_zid`), so the id has to
    /// exist somewhere the C thread can read it. Minting it before the spawn is
    /// also what makes the two equal by construction instead of by convention:
    /// there is one `fresh_zid()` call per session and both readers use it.
    zid: [u8; ZID_LENGTH],
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
    driver: StdMutex<Option<JoinHandle<()>>>,
}

impl SessionState {
    /// This session's own zid (pico `z_info_zid`). Always the id the INIT
    /// carried — see the field.
    pub fn zid(&self) -> [u8; ZID_LENGTH] {
        self.zid
    }

    /// Whether [`Self::close`] has already run (R311y559 — pico
    /// `z_session_is_closed`).
    ///
    /// Reads the SAME `stop` latch the drive loop races against, rather than a
    /// second flag set beside it: a separate "closed" boolean would have to be
    /// kept in step with the latch, and the whole point of the latch is that it
    /// is the one fact both the C thread and the drive thread agree on.
    pub fn is_closed(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

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
/// `None` on OS-entropy failure, which fails the open — the choice the session
/// makes for every per-handshake value it draws: a source that fails leaves no
/// value to use rather than a reused one (`draw_cookie_nonce` in
/// wz-session-core's `session_actions.rs`). Handing back a fixed id instead
/// would reintroduce exactly the peer-collision this exists to prevent.
///
/// (R2783 re-pointed this: it cited `OpenError::AuthEntropy` by line, a
/// variant that no longer exists because no open seam draws a challenge now.)
fn fresh_zid() -> Option<[u8; ZID_LENGTH]> {
    let mut zid = [0u8; ZID_LENGTH];
    getrandom::getrandom(&mut zid).ok()?;
    Some(zid)
}

/// Fixed session-init parameters (mirrors the wz-ap-demo defaults), with a
/// per-session [`fresh_zid`].
///
/// R311y820 — FALLIBLE, and the reason is the same one that already made
/// `fresh_zid` fallible six lines above: this builder needs OS entropy, and
/// there is no honest constant to fall back to. The cookie signing key was
/// `vec![0xAB; 32]`, a literal in a public repository, so every session this C
/// ABI opened as an acceptor minted its anti-amplification cookie under a key
/// anyone could read.
pub(crate) fn init_params(
    whatami: WhatAmI,
    zid: Vec<u8>,
    tx_queue: TxQueueConf,
) -> Result<SessionInitParams, EntropyUnavailable> {
    Ok(SessionInitParams {
        version: 0x09,
        whatami,
        zid,
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 65535,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        tx_queue,
        cookie_signing_key: SigningKey::from_entropy(&mut OsEntropy)?,
    })
}

/// Everything both drive roles need that is not the endpoint itself.
///
/// R311y528 — introduced when threading the session zid through pushed
/// `drive_dial` to eight parameters. Grouping is the right answer rather than a
/// second `#[allow(clippy::too_many_arguments)]`: these six travel TOGETHER by
/// construction — they are exactly the per-session state `open_blocking` mints
/// and hands to whichever role runs — and passing them as one value also removes
/// the argument-order hazard six same-shaped `Arc`s otherwise carry. The
/// pre-existing allow on `drive_listen` came off with it.
struct DriveContext {
    /// This session's own zid, minted on the calling thread so
    /// [`SessionState::zid`] and the INIT cannot disagree.
    zid: [u8; ZID_LENGTH],
    shared: Arc<SharedSession>,
    /// Unblocks `z_open`: `true` once the role has reached its ready point
    /// (handshake settled for dial, bind complete for listen), `false` on any
    /// failure before it.
    tx: mpsc::Sender<bool>,
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
    clock: TokioTime,
    /// The transmit model the calling ABI stands for: zenoh's bounded queue for
    /// zenoh-c, pico's blocking write for zenoh-pico. See [`open_blocking`].
    tx_queue: TxQueueConf,
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
/// the registry, then pump it until `z_close`. `tx` unblocks `z_open` once the
/// handshake has settled — pico's blocking client open — unless `phase` says
/// the open does not wait for its peer, in which case it unblocks first (see
/// the ZA-3298 note in the body).
async fn drive_dial(
    endpoints: Vec<String>,
    whatami: WhatAmI,
    tls: CapiTlsConfig,
    phase: DialPhase,
    ctx: DriveContext,
) {
    let DriveContext {
        zid,
        shared,
        tx,
        shutdown,
        stop,
        clock,
        tx_queue,
    } = ctx;
    // R311y534 — the dial config is BUILT from the caller's TLS material rather
    // than defaulted. Everything that can fail it runs before the handshake, so a
    // bad trust bundle reports an open failure to the C caller.
    //
    // R2948 — for EVERY connect endpoint, not only the first: zenoh-c dials the
    // whole `connect/endpoints` list, and each endpoint carries its own
    // schedule, the global `connect/retry` with its `#retry_period_*` tail on
    // top (`endpoint_schedule`).
    let mut dial_cfgs: Vec<(String, DialConfig)> = Vec::with_capacity(endpoints.len());
    for endpoint in &endpoints {
        match dial_config(&tls, endpoint) {
            Ok(cfg) => dial_cfgs.push((endpoint.clone(), cfg)),
            Err(_) => {
                let _ = tx.send(false);
                return;
            }
        }
    }
    let scheduled: Vec<(String, RetryPolicy)> = endpoints
        .iter()
        .map(|e| (e.clone(), endpoint_schedule(phase.schedule, e)))
        .collect();
    // R311y820 — fallible the way the step above is: report the open failure to
    // the C caller rather than dial with a cookie key anybody could forge.
    // Minted ONCE, before the phase: it is not a connect failure, so it is not
    // what `connect/retry` re-attempts.
    let params = match init_params(whatami, zid.to_vec(), tx_queue) {
        Ok(p) => p,
        Err(_) => {
            let _ = tx.send(false);
            return;
        }
    };
    let dialer = Arc::new(Dialer {
        dial_cfgs,
        params,
        clock,
    });
    // R2950 — the two ROLES connect differently upstream, and each is built
    // here as upstream builds it. A client connects through
    // `connect_peers_single_link` and holds ONE session ("the client mode only
    // allows connecting to a single endpoint", `DEFAULT_CONFIG.json5`); a peer
    // or router through `connect_peers_multiply_links`, which connects to EVERY
    // endpoint it can, each with its own failure policy. See [`drive_peer`].
    if whatami != WhatAmI::Client {
        drive_peer(endpoints, phase, dialer, shared, tx, shutdown, stop).await;
        return;
    }
    let attempt = |endpoint: &str, _attempt: u32| {
        let dialer = dialer.clone();
        let endpoint = endpoint.to_owned();
        async move { dialer.open(&endpoint).await }
    };
    // R2948 — the RE-DIAL list, each endpoint on the re-dial schedule with its
    // own `#` tail on top, run unbounded as upstream's `peers_connector_retry`
    // runs until the endpoint connects or the session is closed.
    let rescheduled: Vec<(String, RetryPolicy)> = match phase.redial {
        Some(redial) => endpoints
            .iter()
            .map(|e| (e.clone(), endpoint_schedule(redial, e)))
            .collect(),
        None => Vec::new(),
    };
    // R2948 — over the whole list, by `drive_connect_phase`: the endpoints that
    // do not retry once each in order, then the retrying ones raced on their own
    // schedules, the first to open winning. A client that did not connect fails
    // its open: upstream's client connect never reads `exit_on_failure`
    // (R2942 correcting R2936, which released a client too).
    let mut session = match drive_connect_phase(phase.policy.budget, &scheduled, &attempt).await {
        Ok(opened) => opened,
        Err(_) => {
            let _ = tx.send(false);
            return;
        }
    };
    let mut released = false;

    loop {
        // A client's session has exactly one peer, so it occupies the single
        // `DIAL_FACE_ID` slot; from here the C surface is role-agnostic (it fans
        // over whatever faces the registry holds). A re-dialled session lands in
        // the same slot, and `face_up` replays the declarations onto it.
        //
        // R311y557 — the LOCAL PLANE's drain is an arm of THIS select, not a
        // `tokio::spawn`. Both placements keep the C application thread out of
        // the C callbacks, which is the `unsafe impl Sync` premise; only this one
        // also keeps the plane's deliveries from overlapping the face's, because a
        // `select!` polls its arms on ONE task while the per-session runtime has
        // two worker threads a spawned task could land on.
        let mut abandoned = false;
        tokio::select! {
            _ = drive_face(
                DIAL_FACE_ID,
                session,
                &shared,
                shutdown_future(shutdown.clone(), stop.clone()),
                || {
                    if !released {
                        abandoned = tx.send(true).is_err();
                    }
                },
            ) => {}
            _ = shared.drive_local_plane() => {}
        }
        if abandoned {
            return;
        }
        released = true;

        // R2948 — a session that ended for any reason but `z_close` has lost its
        // link, and zenoh re-dials the configured endpoints behind it. The latch is
        // what `z_close` sets before it notifies, so it tells the two apart.
        if stop.load(Ordering::SeqCst) || rescheduled.is_empty() {
            return;
        }
        let redialing = drive_connect_phase(PhaseBudget::UNBOUNDED, &rescheduled, &attempt);
        session = tokio::select! {
            again = redialing => match again {
                Ok(again) => again,
                Err(_) => return,
            },
            _ = shared.drive_local_plane() => return,
            _ = shutdown_future(shutdown.clone(), stop.clone()) => return,
        };
    }
}

/// Drive ONE established face until its session ends or `closing` fires, then
/// take the face down and drain it. `on_up` runs once the face is registered,
/// which is where a client's open is released.
///
/// R2950 — split out of the dial loop so a client's one face and a peer's
/// per-endpoint faces run the same body: the ordering arguments below are the
/// whole of its correctness, and a second copy would be a second place for
/// them to rot.
async fn drive_face(
    face: u64,
    session: OpenedSession,
    shared: &Arc<SharedSession>,
    closing: impl std::future::Future<Output = ()>,
    on_up: impl FnOnce(),
) {
    // R2455 — an `OpenedSession` dismantles ONLY through `into_parts`, which is
    // what carries the writer handle out by name rather than letting it fall
    // out of a capture (`OpenedSession`'s `Drop` impl states the rule). This
    // task holds it for the whole drive below.
    let OpenedSessionParts {
        mut engine,
        actions,
        inbound,
        writer_handle,
        clock,
        ..
    } = session.into_parts();
    shared.face_up(face, &actions);
    on_up();

    let mut driver = inbound;
    let timeouts = SessionTimeouts::spec_defaults();
    let dispatch_shared = shared.clone();
    // The `IterationEvent<'_>` annotation is load-bearing: `drive_session_until_terminal`
    // needs a HIGHER-RANKED `FnMut(IterationEvent<'_>)`, and without it inference
    // pins the closure to one specific lifetime ("implementation of `FnMut` is not
    // general enough").
    let mut dispatch = |event: IterationEvent<'_>| dispatch_shared.dispatch(face, event);
    // R311y296 — the dial role does NOT go through `accept_loop`, so the
    // `FaceForwarder::next_extra_deadline_ms` hook that arms the accepted
    // faces' wakes cannot reach it; this closure is the dial role's equivalent,
    // passed straight to the drive. Both roles therefore sweep expired `z_get`s
    // on their own drive thread at the deadline rather than on the ~3333 ms
    // keepalive cadence — a `connect` session is the ordinary pico get client
    // (a `z_get` to a router), so leaving this path on the plain drive would
    // have made the sweep late exactly where it matters most.
    let deadline_shared = shared.clone();
    let next_deadline = move || deadline_shared.next_reply_deadline_ms(face);
    // `face_up` above registered the face, so its re-arm signal exists.
    let revised = shared.deadline_revised(face);

    // The local plane is NOT an arm here: a session holds one plane however
    // many faces it has, so the caller drives it once (R311y557's reason,
    // stated at the call sites).
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
            // R2702/R2703 — no session-owned stages: the C API drives a session
            // whose §5.16 policy and whose subscriptions, if any, belong to the
            // embedding application, and this loop does not own one.
            wz_runtime_tokio::session_glue::LoopStages {
                // The parameter type is named rather than inferred: inside the
                // bundle, `|_| {}` infers a closure that is not general enough
                // over the outcome's lifetime, and rustc reports it as
                // "implementation of `FnMut` is not general enough" at the
                // `select!` rather than at the closure.
                ingress: |_: &mut wz_runtime_tokio::session_glue::DriverLoopOutcome| {},
                after_dispatch: || core::future::ready(()),
            },
        ) => {}
        _ = closing => {}
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
    shared.face_down(face);
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

/// The PEER connect: upstream's `connect_peers_multiply_links`
/// (`zenoh/src/net/runtime/orchestrator.rs` @
/// `async fn connect_peers_multiply_links(&self, peers: &[EndPoints]) -> ZResult<()> {`),
/// with each connected endpoint as a face of its own.
///
/// R2950. Every endpoint is walked in order and forks on ITS arm — the global
/// `connect/timeout_ms` and `connect/exit_on_failure` with its `#` tail on top
/// ([`endpoint_policy`], [`endpoint_schedule`]):
///
/// - one attempt, and a failure either fails the open or is stepped over;
/// - retried until it connects, holding the open up;
/// - retried in the background, the open not waiting past the start window.
///
/// `connect/timeout_ms` bounds that whole walk, as upstream's outer timeout
/// does, and a walk that runs out of it fails the open. The background
/// endpoints are then waited for up to `start_window` (`scouting/delay` under
/// `open/return_conditions/connect_scouted`) before the open returns.
///
/// Each connected endpoint gets its OWN face, drive, drain and re-dial — the
/// face ids are `DIAL_FACE_ID + i`, which cannot meet the accept loop's ids
/// because a session dials or listens, never both. The faces run on a
/// `LocalSet`, because a session's drive futures are not `Send`, and on this
/// task, so none of them can outlive the session's runtime.
#[allow(clippy::too_many_arguments)]
async fn drive_peer(
    endpoints: Vec<String>,
    phase: DialPhase,
    dialer: Arc<Dialer>,
    shared: Arc<SharedSession>,
    tx: mpsc::Sender<bool>,
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
) {
    let (closing_tx, closing_rx) = tokio::sync::watch::channel(false);
    let window = Arc::new(StartWindow::default());
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut faces: Vec<tokio::task::JoinHandle<()>> = Vec::new();
            let deadline = phase
                .policy
                .budget
                .deadline()
                .map(|d| tokio::time::Instant::now() + d);
            let mut failed = false;
            for (i, endpoint) in endpoints.iter().enumerate() {
                let policy = endpoint_policy(phase.policy, endpoint);
                let schedule = endpoint_schedule(phase.schedule, endpoint);
                let arm = policy.arm(schedule);
                let leg = FaceLeg {
                    face: DIAL_FACE_ID + i as u64,
                    endpoint: endpoint.clone(),
                    redial: phase.redial.map(|r| endpoint_schedule(r, endpoint)),
                    dialer: dialer.clone(),
                    shared: shared.clone(),
                    closing: closing_rx.clone(),
                    window: window.clone(),
                };
                match arm {
                    PhaseArm::OnceThenFail | PhaseArm::OnceThenSkip => {
                        match within(deadline, dialer.open(endpoint)).await {
                            // The walk's budget ran out: upstream's outer
                            // timeout fails the whole connect.
                            None => {
                                failed = true;
                                break;
                            }
                            Some(Ok(session)) => {
                                faces.push(tokio::task::spawn_local(leg.run(Some(session), None)))
                            }
                            Some(Err(())) if arm.ends_startup() => {
                                failed = true;
                                break;
                            }
                            Some(Err(())) => {}
                        }
                    }
                    PhaseArm::RetryThenFail => {
                        let retried = drive_phase(
                            PhasePolicy {
                                budget: PhaseBudget::UNBOUNDED,
                                ..policy
                            },
                            schedule,
                            |_| dialer.open(endpoint),
                        );
                        match within(deadline, retried).await {
                            Some(Ok(session)) => {
                                faces.push(tokio::task::spawn_local(leg.run(Some(session), None)))
                            }
                            // Unbounded, so only the walk's budget ends it.
                            _ => {
                                failed = true;
                                break;
                            }
                        }
                    }
                    PhaseArm::RetryInBackground => {
                        window.expect_one();
                        faces.push(tokio::task::spawn_local(leg.run(None, Some(schedule))));
                    }
                }
            }
            if failed {
                let _ = closing_tx.send(true);
                for face in faces {
                    let _ = face.await;
                }
                let _ = tx.send(false);
                return;
            }
            // The start window: the background endpoints, up to the window.
            if let Some(span) = phase.start_window {
                window.wait(span).await;
            }
            if tx.send(true).is_err() {
                let _ = closing_tx.send(true);
                for face in faces {
                    let _ = face.await;
                }
                return;
            }
            // R311y557 — the local plane on THIS task, beside the faces' tasks
            // on the same `LocalSet`: one thread, so its deliveries cannot
            // overlap a face's.
            tokio::select! {
                _ = shared.drive_local_plane() => {}
                _ = shutdown_future(shutdown.clone(), stop.clone()) => {}
            }
            let _ = closing_tx.send(true);
            for face in faces {
                let _ = face.await;
            }
        })
        .await;
}

/// `fut`, bounded by `deadline` when there is one.
async fn within<T>(
    deadline: Option<tokio::time::Instant>,
    fut: impl std::future::Future<Output = T>,
) -> Option<T> {
    match deadline {
        Some(at) => tokio::time::timeout_at(at, fut).await.ok(),
        None => Some(fut.await),
    }
}

/// The background endpoints a peer's open waits for, and the wake that tells
/// it one connected — upstream's `start_conditions`.
#[derive(Default)]
struct StartWindow {
    pending: std::sync::atomic::AtomicUsize,
    connected: Notify,
}

impl StartWindow {
    fn expect_one(&self) {
        self.pending.fetch_add(1, Ordering::SeqCst);
    }

    fn one_connected(&self) {
        self.pending.fetch_sub(1, Ordering::SeqCst);
        self.connected.notify_one();
    }

    /// Until every expected endpoint connected, or `span` passed.
    async fn wait(&self, span: std::time::Duration) {
        let until = tokio::time::Instant::now() + span;
        while self.pending.load(Ordering::SeqCst) > 0 {
            if tokio::time::timeout_at(until, self.connected.notified())
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

/// One peer endpoint's face for the session's life: connect, drive, drain,
/// re-dial.
struct FaceLeg {
    face: u64,
    endpoint: String,
    /// The re-dial schedule after a lost link, `None` for none.
    redial: Option<RetryPolicy>,
    dialer: Arc<Dialer>,
    shared: Arc<SharedSession>,
    closing: tokio::sync::watch::Receiver<bool>,
    window: Arc<StartWindow>,
}

impl FaceLeg {
    /// Drive this endpoint's face from `first` (already connected) or by
    /// connecting on `schedule` (a background endpoint), until the session
    /// closes. A background endpoint's first connect is what the start window
    /// waits on.
    async fn run(self, first: Option<OpenedSession>, schedule: Option<RetryPolicy>) {
        let mut session = first;
        let mut connecting = schedule;
        let mut counts_for_window = session.is_none();
        loop {
            let opened = match session.take() {
                Some(opened) => opened,
                None => {
                    let Some(schedule) = connecting.take() else {
                        return;
                    };
                    let mut closing = self.closing.clone();
                    let dialed = drive_phase(
                        PhasePolicy {
                            budget: PhaseBudget::UNBOUNDED,
                            exit_on_failure: false,
                        },
                        schedule,
                        |_| self.dialer.open(&self.endpoint),
                    );
                    tokio::select! {
                        dialed = dialed => match dialed {
                            Ok(opened) => opened,
                            Err(_) => return,
                        },
                        _ = closing.wait_for(|c| *c) => return,
                    }
                }
            };
            if counts_for_window {
                counts_for_window = false;
                self.window.one_connected();
            }
            let mut closing = self.closing.clone();
            drive_face(
                self.face,
                opened,
                &self.shared,
                async move {
                    let _ = closing.wait_for(|c| *c).await;
                },
                || {},
            )
            .await;
            // R2948's rule, per face: a face that ended for any reason but
            // `z_close` has lost its link, and upstream re-dials that endpoint
            // (`closed_link` -> `peer_connector_retry`).
            if *self.closing.borrow() {
                return;
            }
            connecting = self.redial;
        }
    }
}

/// The TLS material a C-ABI `z_open` carries, already RESOLVED to PEM bytes.
///
/// R311y534 — this replaces the two `Option<String>` listen-cert PATHS the quic
/// acceptor used to take, and the reason is that the pico key set is wider than
/// a pair of paths in two independent directions. Each certificate value has a
/// PATH form and a `*_BASE64` inline form (`Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY`
/// vs `..._BASE64_KEY`), and the upstream examples use the INLINE one by default
/// — their PEM blobs are compiled into the program. And the dial side needs
/// material the listen side never did: a root CA to verify the peer against, a
/// name-verification policy, and an optional client cert for mTLS.
///
/// So the shim resolves "path or base64" ONCE, on the ABI side where the key
/// numbers live, and hands PEM BYTES across. That keeps this crate free of
/// key-encoding knowledge and makes the two forms indistinguishable downstream,
/// which is what they are: `-C ca.pem` and the inline bundle are the same trust
/// decision written two ways.
///
/// All fields default to `None`/`false`, which is the cert-free tcp/udp/ws path
/// — [`Default`] is what a non-TLS `z_open` passes.
#[derive(Default, Clone, Debug)]
pub struct CapiTlsConfig {
    /// The trust bundle a `tls/...` DIAL verifies the peer's server cert
    /// against (pico `Z_CONFIG_TLS_ROOT_CA_CERTIFICATE{,_BASE64}_KEY`). `None`
    /// leaves a `tls/...` dial without TLS material, which the runtime reports
    /// as an unsupported dial rather than silently dialing in the clear.
    pub root_ca_pem: Option<Vec<u8>>,
    /// Whether the peer cert's SAN must match the dialed host (pico
    /// `Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY`). pico's own default is
    /// `false`, and the stock examples rely on it: they dial a numeric
    /// `tls/127.0.0.1:<port>` while their bundled cert names `localhost`.
    pub verify_name_on_connect: bool,
    /// The client cert a MUTUAL-TLS dial presents (pico
    /// `Z_CONFIG_TLS_CONNECT_CERTIFICATE{,_BASE64}_KEY` + its private key),
    /// gated by `Z_CONFIG_TLS_ENABLE_MTLS_KEY`. Both-or-neither.
    pub connect_cert_pem: Option<Vec<u8>>,
    pub connect_key_pem: Option<Vec<u8>>,
    /// The cert chain + private key a `tls/...` or `quic/...` LISTEN presents
    /// (pico `Z_CONFIG_TLS_LISTEN_{CERTIFICATE,PRIVATE_KEY}{,_BASE64}_KEY`).
    /// zenoh feeds ONE tls block to both backends, so one pair serves both.
    pub listen_cert_pem: Option<Vec<u8>>,
    pub listen_key_pem: Option<Vec<u8>>,
    /// Require and verify a CLIENT cert on the accept side (pico
    /// `Z_CONFIG_TLS_ENABLE_MTLS_KEY` read by a listener). The bundle is
    /// [`Self::root_ca_pem`], mirroring pico, which uses the one CA value for
    /// both roles.
    pub require_client_auth: bool,
}

impl CapiTlsConfig {
    /// The mTLS client-auth pair, `Some` only when BOTH halves are present.
    ///
    /// Separate from the fields because "mTLS enabled" and "the material for it
    /// arrived" are two conditions, and a half-configured pair must not silently
    /// degrade to one-way TLS.
    #[cfg(feature = "transport-link-tls")]
    fn client_auth(&self) -> Option<wz_runtime_tokio::tls_config::ClientAuthPem<'_>> {
        match (&self.connect_cert_pem, &self.connect_key_pem) {
            (Some(cert), Some(key)) => Some(wz_runtime_tokio::tls_config::ClientAuthPem {
                cert_chain_pem: cert,
                private_key_pem: key,
            }),
            _ => None,
        }
    }
}

/// The HOST of a `<scheme>/<host>:<port>` locator, for use as the TLS SNI /
/// verified name.
///
/// rustls takes the name as an explicit value rather than deriving it from the
/// socket address, so a dial has to say which name it is talking to. pico
/// derives the same thing from its own locator (`_z_endpoint_t`'s address), so
/// taking it from the locator here is the faithful reading rather than a
/// convenience — and it is what makes `verify_name_on_connect=true` mean
/// something, since a hard-coded name would verify a cert against a constant.
///
/// Returns `None` for a locator with no `<scheme>/` prefix or no host.
fn locator_host(endpoint: &str) -> Option<&str> {
    let rest = endpoint.split_once('/')?.1;
    // Strip a query/config suffix (`tcp/1.2.3.4:7447?foo=bar`) before the port,
    // then the port itself. An IPv6 literal is bracketed, so the LAST colon is
    // the port separator in every form the locator grammar allows.
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let host = match rest.rsplit_once(':') {
        Some((host, _port)) => host,
        None => rest,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then_some(host)
}

/// Build the LISTEN [`AcceptConfig`] from the resolved TLS material.
///
/// R311y534 — this now fills BOTH acceptor slots from the one cert pair, which
/// is what zenoh does (one tls block, two backends) and what pico's key names
/// already implied. Before, only the quic slot was filled, so a
/// `z_open(listen="tls/..")` carrying a perfectly good cert still bound to a
/// typed `Unsupported`: the material was present and the slot it belonged in was
/// never set. Each slot is independently feature-gated, so a build with one
/// backend and not the other fills only the slot it has.
///
/// Both-or-neither on the pair: a listener told to present a cert with no key is
/// a configuration error, not a cert-free listener.
fn listen_accept_config(tls: &CapiTlsConfig) -> std::io::Result<AcceptConfig> {
    let cfg = AcceptConfig::default();
    let (cert, key) = match (&tls.listen_cert_pem, &tls.listen_key_pem) {
        (Some(cert), Some(key)) => (cert, key),
        (None, None) => return Ok(cfg),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a cert-bearing listen needs BOTH the listen certificate and private-key \
                 config values",
            ))
        }
    };

    #[cfg(feature = "transport-link-tls")]
    let cfg = {
        use wz_runtime_tokio::session_open::TlsAcceptConfig;
        // The mTLS client-CA bundle is the SAME root-CA value pico uses for the
        // dial side; pico carries one CA per config, not one per direction.
        let client_ca = tls
            .require_client_auth
            .then_some(tls.root_ca_pem.as_deref())
            .flatten();
        cfg.with_tls(TlsAcceptConfig::from_pem(cert, key, client_ca)?)
    };

    #[cfg(feature = "transport-link-quic")]
    let cfg = {
        use wz_runtime_tokio::session_open::QuicAcceptConfig;
        cfg.with_quic(QuicAcceptConfig::from_cert_key_pem(cert, key)?)
    };

    // Neither backend compiled in: the cert material is inert because a `tls/` or
    // `quic/` listen surfaces the runtime's typed `Unsupported` at bind anyway.
    #[cfg(not(any(feature = "transport-link-tls", feature = "transport-link-quic")))]
    let _ = (cert, key);

    Ok(cfg)
}

/// Build the DIAL [`DialConfig`] from the resolved TLS material — the dial
/// mirror of [`listen_accept_config`], and new at R311y534.
///
/// Before it existed the C ABI dialed with [`DialConfig::default`] unconditionally,
/// so a `tls/...` connect had no trust bundle and no name to verify and could not
/// complete a handshake at all, regardless of what the caller had configured.
///
/// R2603 (open-debt 727) — it no longer bails when the caller configured no root
/// CA. That bail was correct on its own premise, which it stated: without a
/// configured CA there was nothing to verify the peer against, so it returned
/// the cert-free default and let the runtime report an unsupported dial "rather
/// than this function inventing a trust policy". 727 overturns the premise. A
/// trust policy now EXISTS one layer down — `server_trust_roots` seeds the
/// public WebPKI roots, as zenoh does — so this function invents nothing by
/// passing the caller's `Option` straight through: `None` means the public
/// roots, which is what a pico application dialing a publicly-trusted peer
/// expects and what it could not get before.
fn dial_config(tls: &CapiTlsConfig, endpoint: &str) -> std::io::Result<DialConfig> {
    let cfg = DialConfig::default();
    let root_ca = tls.root_ca_pem.as_deref();
    // The dialed host doubles as SNI and, under `Verify`, as the name checked
    // against the peer cert's SAN.
    let server_name = locator_host(endpoint).unwrap_or("localhost");

    #[cfg(feature = "transport-link-tls")]
    let cfg = {
        use wz_runtime_tokio::session_open::TlsDialConfig;
        use wz_runtime_tokio::tls_config::ServerNameVerification;
        let verification = if tls.verify_name_on_connect {
            ServerNameVerification::Verify
        } else {
            ServerNameVerification::AnyName
        };
        cfg.with_tls(TlsDialConfig::from_pem(
            root_ca,
            server_name,
            tls.client_auth(),
            verification,
        )?)
    };

    #[cfg(feature = "transport-link-quic")]
    let cfg = {
        use wz_runtime_tokio::session_open::QuicDialConfig;
        cfg.with_quic(QuicDialConfig::from_ca_pem(root_ca, server_name)?)
    };

    #[cfg(not(any(feature = "transport-link-tls", feature = "transport-link-quic")))]
    let _ = (root_ca, server_name);

    Ok(cfg)
}

/// The `listen` role: bind, unblock `z_open` immediately, then hold N
/// concurrent inbound peers until `z_close` — pico's non-blocking listener.
async fn drive_listen(endpoint: String, tls: CapiTlsConfig, ctx: DriveContext) {
    let DriveContext {
        zid,
        shared,
        tx,
        shutdown,
        stop,
        clock,
        tx_queue,
    } = ctx;
    // Everything that can fail the open runs BEFORE the success signal below,
    // so a failure is reported to the C caller rather than silently killing a
    // listener it was told had opened.
    // R311y406 / R311y534 — thread the LISTEN server cert (native
    // Z_CONFIG_TLS_LISTEN_* keys, path or inline base64) into the bind's
    // AcceptConfig, so a `z_open(listen="tls/..")` or `z_open(listen="quic/..")`
    // carrying the cert presents it (was a cert-free `bind_endpoint` ->
    // cert-absence reject). Each backend's slot is filled only when its feature
    // is compiled in; without it that scheme surfaces `Unsupported` at bind
    // regardless -- see `listen_accept_config`.
    let accept_cfg = match listen_accept_config(&tls) {
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
    // accept loop's runtime `AcceptedLink::supports_mesh_multi_peer` backstop.
    //
    // ⛔ R2723 -- THIS NO LONGER REFUSES, for the reason its `run_router` twin
    // records: the guard rejected any acceptor that could not yield N CONCURRENT
    // peers, which since R311y805 has meant serial alone, so a
    // `z_open(listen="serial/...")` returned `Z_ERR_GENERIC`. R2722 gave the
    // serial listener link-liveness feedback, so it serves peers one AT A TIME
    // and feeds the accept loop like any other listener. The predicate is still
    // true, and its `run_router` twin REPORTS it; this crate does not, because it
    // has no logging dependency and adding one so a C-ABI core can emit a single
    // advisory line would be a heavier trade than the line is worth. Its only
    // channel to a caller is `tx.send(bool)`, which says opened-or-not and has no
    // room for an advisory -- so the guard is gone rather than turned into an
    // empty block dressed as one.
    // R311y820 — drawn HERE, above the `tx.send(true)` below, and the placement
    // is the point: after that send the C caller has already been told the open
    // succeeded, so an entropy failure could only be reported as "no peer ever
    // connects". Built before the bind is announced, it is an ordinary open
    // failure like the two above.
    let params = match init_params(WhatAmI::Peer, zid.to_vec(), tx_queue) {
        Ok(p) => p,
        Err(_) => {
            let _ = tx.send(false);
            return;
        }
    };
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
    let local_shared = shared.clone();
    let forwarder = CApiForwarder::new(shared);
    // R311y557 — the LISTEN role is where the local plane matters most: a
    // listener is unblocked by the BIND, so every put it makes before its first
    // peer connects had nowhere to deliver in-process. The drain rides this
    // task's `select!` for the same one-task reason `drive_dial` does.
    tokio::select! {
        _summary = accept_loop(
            listener,
            params,
            clock,
            DEFAULT_OPEN_TICK_MS,
            shutdown_future(shutdown, stop),
            |_event| {},
            &forwarder,
        ) => { let _ = _summary; }
        _ = local_shared.drive_local_plane() => {}
    }
}

/// Open a session: spawn the drive thread and wait for the role's open
/// outcome. For `connect` that is the settled handshake; for `listen` it is
/// only the bind.
///
/// `dial_phase` decides how long the `connect` role keeps trying before it
/// reports the failure; the `listen` role does not read it.
///
/// `tx_queue` is the transmit model of the ABI calling this, and it is a
/// parameter because the two ABIs this core serves transmit differently: a
/// zenoh-c session puts onto zenoh's bounded queue and drops a droppable
/// message after `wait_before_drop` ([`TxQueueConf::default`]), while pico
/// writes on the caller's thread and never drops for a full socket
/// ([`TxQueueConf::pico`]).
pub fn open_blocking(
    connect: Vec<String>,
    listen: Option<String>,
    tls: CapiTlsConfig,
    dial_whatami: WhatAmI,
    dial_phase: DialPhase,
    tx_queue: TxQueueConf,
) -> Result<SessionState, OpenError> {
    let clock = TokioTime::new();
    // Minted here, on the CALLING thread, so `SessionState` can hand it to
    // `z_info_zid` and the INIT cannot disagree with it — see the field doc.
    let zid = fresh_zid().ok_or(OpenError::DriveFailed)?;
    // R311y820 — one line below `fresh_zid`, and fallible for the same reason:
    // both need OS entropy and neither has an honest constant to fall back to.
    let shared =
        Arc::new(SharedSession::new(clock, zid.to_vec()).map_err(|_| OpenError::DriveFailed)?);
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
            let ctx = DriveContext {
                zid,
                shared: drive_shared,
                tx,
                shutdown: drive_shutdown,
                stop: drive_stop,
                clock,
                tx_queue,
            };
            rt.block_on(async move {
                match (connect.is_empty(), listen) {
                    (false, _) => {
                        drive_dial(connect, dial_whatami, tls, dial_phase, ctx).await;
                    }
                    (true, Some(endpoint)) => {
                        drive_listen(endpoint, tls, ctx).await;
                    }
                    (true, None) => {
                        let _ = ctx.tx.send(false);
                    }
                }
            });
            // `rt` is dropped here, after the drive loop has returned.
        })
        .map_err(|_| OpenError::DriveFailed)?;

    match rx.recv() {
        Ok(true) => Ok(SessionState {
            shared,
            zid,
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

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Mutex as StdMutex;
use std::sync::{Arc, Condvar};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::sync::Notify;

use wz_runtime_tokio::accept_loop::{
    accept_loop_offering, accept_loop_offering_spawned, DialIntent, DialIntentReceiver,
    DialIntentSender, FaceExecutor, SpawnedDrive,
};
use wz_runtime_tokio::gossip_plane::GossipPolicy;
use wz_runtime_tokio::node_clock::{NodeHlc, TimestampingEnabled};
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::LocalDeliveryDrain;
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal_with_extra_deadline, EntropyUnavailable, ExtraDeadline,
    IterationEvent, OsEntropy, SessionInitParams, SessionTimeouts, SigningKey, TxQueueConf,
    WhatAmI,
};
use wz_runtime_tokio::session_open::{
    bind_endpoint_with_config, dial_endpoint, initiate_and_open_session_with_offer,
    offer_for_connect, AcceptConfig, BoundListener, DialConfig, OpenedSession, OpenedSessionParts,
    SessionOffer, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::startup_phase::{
    drive_bind_phase, drive_connect_phase, drive_phase, endpoint_policy, endpoint_schedule,
    retry_until_bound, PhaseArm, PhaseBudget, PhasePolicy,
};

use crate::faces::{
    CApiForwarder, GossipSetup, OpenShmClients, SessionResources, SharedSession, DIAL_FACE_ID,
};
use crate::scouting_node::{
    bind_responder, Advertised, LateLocators, Responder, ScoutLink, ScoutingPlan,
};

/// How the dial half of an open treats an attempt that fails — zenoh's
/// `connect/timeout_ms` and `connect/exit_on_failure` ([`PhasePolicy`]) with the
/// `connect/retry` schedule that paces it ([`RetryPolicy`]), already resolved
/// for the role the session dials as.
///
/// The two halves are the runtime's own types and the loop that runs
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
    /// R3125 -- how long a ROUTER's open is held after its halves have started: `scouting/delay`,
    /// slept in full whether or not the router scouts and whatever its connects did, as upstream's
    /// `start_router` ends (`zenoh/src/net/runtime/orchestrator.rs` @
    /// `tokio::time::sleep(delay).await;`). A peer's wait is [`Self::start_window`], which ends as
    /// soon as its start conditions are met; a router has none and waits the delay out. Read only
    /// for a session that dials as a router; zero for an ABI that has no router role.
    pub router_hold: std::time::Duration,
}

impl DialPhase {
    /// One attempt, and a failure fails the open: upstream's client column,
    /// and what every open here did before the connect keys were read.
    pub const ONCE: Self = Self {
        policy: PhasePolicy::CONNECT_CLIENT_DEFAULT,
        schedule: RetryPolicy::ZENOH_DEFAULT,
        redial: None,
        start_window: None,
        router_hold: std::time::Duration::ZERO,
    };
}

/// How the bind half of an open treats an endpoint that cannot be bound -- zenoh's
/// `listen/timeout_ms` and `listen/exit_on_failure` ([`PhasePolicy`]) with the `listen/retry`
/// schedule that paces it ([`RetryPolicy`]), already resolved for the role the session plays.
///
/// R3089 -- the bind twin of [`DialPhase`], and run by the runtime's own transcription of
/// upstream's `bind_listeners` ([`drive_bind_phase`]), so a C open cannot drift from the node's.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ListenPhase {
    /// `listen/timeout_ms` + `listen/exit_on_failure`.
    pub policy: PhasePolicy,
    /// `listen/retry`.
    pub schedule: RetryPolicy,
}

impl ListenPhase {
    /// What upstream ships for every role: one attempt per endpoint, and a failure fails the
    /// open. What every open here did before the listen keys were read.
    pub const SHIPPED: Self = Self {
        policy: PhasePolicy::LISTEN_DEFAULT,
        schedule: RetryPolicy::ZENOH_DEFAULT,
    };
}

/// Everything ONE dial attempt needs, owned, so a peer's per-endpoint faces
/// can each hold it on their own task.
struct Dialer {
    /// Each endpoint's dial config, built before any dial so a bad trust bundle
    /// fails the open rather than one attempt.
    dial_cfgs: Vec<(String, DialConfig)>,
    params: SessionInitParams,
    /// What every link this session dials offers at its handshake. See
    /// [`open_blocking`].
    offer: SessionOffer,
    clock: TokioTime,
    /// R3070 -- the trust material every dial is built from, kept so a locator the session
    /// FINDS (one no `dial_cfgs` entry was built for) is dialled the way a configured one is.
    tls: CapiTlsConfig,
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
        self.open_with(endpoint, dial_cfg).await
    }

    /// Dial a locator the session found by scouting and open a session to `expected`, the node
    /// that answered from it. Upstream's `open_transport_unicast_with_zid`: a link that opens to
    /// another node than the Hello named is not the connection that was wanted, and is closed.
    async fn open_scouted(&self, locator: &str, expected: &[u8]) -> Result<OpenedSession, ()> {
        let dial_cfg = dial_config(&self.tls, locator).map_err(|_| ())?;
        let session = self.open_with(locator, &dial_cfg).await?;
        if is_expected_peer(session.peer_zid().as_deref(), expected) {
            Ok(session)
        } else {
            session.drain_to_close().await;
            Err(())
        }
    }

    async fn open_with(&self, endpoint: &str, dial_cfg: &DialConfig) -> Result<OpenedSession, ()> {
        // The endpoint's own QoS band rides the node's offer, as upstream's
        // opener reads it off the endpoint it dials.
        let offer = offer_for_connect(self.offer, endpoint).map_err(|_| ())?;
        let dialed = dial_endpoint(endpoint, dial_cfg).await.map_err(|_| ())?;
        initiate_and_open_session_with_offer(
            dialed,
            self.params.clone(),
            offer,
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

// --- the read task ---------------------------------------------------------

/// Whether the session's drive is being RUN: zenoh-pico's background executor,
/// as a C program sees it.
///
/// pico spawns the keep-alive, lease, read and accept tasks onto an executor when
/// it opens a session, and starts that executor only `if (opts.auto_start_read_task)`
/// (`vendor/zenoh-pico/src/api/api.c` @ `if (opts.auto_start_read_task) {`).
/// `zp_stop_read_task` stops it and `zp_start_read_task` starts it again, both
/// idempotent, and `zp_read_task_is_running` answers whether it is started
/// (`vendor/zenoh-pico/src/runtime/background_executor.c` @
/// `z_result_t _z_background_executor_inner_stop(`). While it is stopped the
/// session reads nothing, sends no keep-alive, checks no lease and accepts no
/// peer, and what arrives waits in the socket. A program relies on that: it opens
/// without the task, declares its subscribers, and starts it, so that nothing is
/// delivered to a subscriber that did not exist yet.
///
/// Every role of a wz session is driven by ONE future on the session's drive
/// thread (the accept loop holds every accepted face, a peer's faces are local
/// tasks that run only when it is polled), so the executor is one switch:
/// `Pausable` stops polling that future while the task is stopped. The faces
/// also wait here (`wait_running`) right after their open, before they read
/// a frame, so frames already in the socket when `z_open` returns are not read in
/// the same poll that announced the open.
///
/// The OPEN itself is never gated: pico connects a client and binds a listener
/// inside `z_open`, before its executor could run, and the gate passes until the
/// role has announced that the open is done (`mark_opened`). Closing
/// always passes, or the drive thread could never end.
///
/// A stop is SYNCHRONOUS, as pico's is: pico suspends its executor and joins the
/// executor's thread (`vendor/zenoh-pico/src/runtime/background_executor.c` @
/// `_Z_SET_IF_OK(ret, _z_task_join(&task_to_join));`), so when `zp_stop_read_task`
/// returns no callback is running and none will run. [`ReadGate::stop`] wakes the
/// drive thread and waits until it has parked, which is after whatever callback
/// it was inside has returned. A stop or a start made ON the drive thread, which
/// is where every callback runs, is REFUSED and changes nothing, as pico refuses
/// both from its executor's thread (`vendor/zenoh-pico/src/runtime/background_executor.c`
/// @ `return _Z_ERR_INVALID;  // suspend cannot be called from executor thread`);
/// waiting there would be waiting for itself.
pub struct ReadGate {
    /// pico's `_started`.
    running: AtomicBool,
    /// Whether the role has announced the open to the caller.
    opened: AtomicBool,
    /// Set by [`SessionState::close`].
    closing: AtomicBool,
    /// Whoever is parked on this gate.
    wakers: StdMutex<Vec<Waker>>,
    /// Every gated future that is alive and has been polled: the top-level drive and
    /// each spawned face. A stop waits for ALL of them (see [`GateTasks`]).
    tasks: StdMutex<GateTasks>,
    /// How many stops have been asked for.
    stop_epoch: AtomicU64,
    /// Signalled when a task parks or ends, and when the wait must end.
    parked: Condvar,
    /// Where the faces of the session are driven: see [`FaceDrive`]. The gate is the
    /// session's executor, which is why the choice lives here and travels with it to every
    /// place that spawns a face.
    face_drive: FaceDrive,
}

/// Where the data plane of each face of a session runs: the read, the decode and the
/// delivery to the C callbacks.
///
/// This is the ABI's contract and not a tuning knob. zenoh-pico's callbacks all run on the
/// session's one read task, so a program written for it does not lock what its callbacks
/// share, and a stop of the read task is a stop of every callback ([`ReadGate`]). zenoh-c's
/// callbacks are documented as concurrent (`CClosure` is `Sync`), and its receive runtime
/// serves each link on its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FaceDrive {
    /// Every face is driven on the session's drive thread, one at a time: zenoh-pico's.
    #[default]
    Serial,
    /// Every face is driven on a thread of its own, so that a callback that blocks, or just
    /// runs long, holds up its own link and no other: zenoh-c's. The control plane (the accept
    /// loop, the handshakes, the dials) stays on the drive thread.
    PerFace,
}

/// The gated futures of one session, which is what a synchronous stop has to wait for.
///
/// A node's callbacks run on more than one thread once each face is a task of its own, so
/// "the drive thread has parked" became "every task that can run a callback has parked".
/// A task is registered by its first poll (a future never polled holds nothing) and leaves
/// when it is dropped, so a stop never waits for one that is gone.
#[derive(Default)]
struct GateTasks {
    next: u64,
    slots: BTreeMap<u64, TaskSlot>,
}

/// One gated future's place in the gate.
struct TaskSlot {
    /// Its own waker, refreshed on each poll, so a stop can make it look at the gate even
    /// while it is idle.
    waker: Option<Waker>,
    /// The newest stop this task has parked for.
    parked_for: u64,
}

thread_local! {
    /// The gates whose gated futures this thread is polling right now, innermost last. A
    /// callback of a session runs inside one of those polls, so "this thread is inside the
    /// gate's poll" is "this is a callback of the session": the test that a stop or a start
    /// from a callback is refused, which pico does from its executor's thread.
    static POLLING: core::cell::RefCell<Vec<usize>> = const { core::cell::RefCell::new(Vec::new()) };
}

/// A start or a stop was made from inside the session's own callbacks. pico
/// answers `_Z_ERR_INVALID` and does nothing, and so does this ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalledFromReadTask;

impl ReadGate {
    /// A gate whose task runs from the start when `running`, and that otherwise
    /// holds the session as soon as its open has been announced.
    fn new(running: bool) -> Self {
        Self {
            running: AtomicBool::new(running),
            opened: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            wakers: StdMutex::new(Vec::new()),
            tasks: StdMutex::new(GateTasks::default()),
            stop_epoch: AtomicU64::new(0),
            parked: Condvar::new(),
            face_drive: FaceDrive::Serial,
        }
    }

    /// The same gate, for a session whose faces are driven as `face_drive` says.
    fn with_face_drive(mut self, face_drive: FaceDrive) -> Self {
        self.face_drive = face_drive;
        self
    }

    fn face_drive(&self) -> FaceDrive {
        self.face_drive
    }

    /// Whether the calling thread is inside a poll of one of THIS gate's futures, which is
    /// where every callback of the session runs. Another session's gate is not this one:
    /// a callback of one session may stop another.
    fn in_callback(&self) -> bool {
        let this = self as *const ReadGate as usize;
        POLLING.with(|polling| polling.borrow().contains(&this))
    }

    /// The role has reached its ready point: from here a stopped task holds the
    /// session. Called BEFORE the caller is told, so a program that stops the task
    /// the moment `z_open` returns finds the gate already armed.
    fn mark_opened(&self) {
        self.opened.store(true, Ordering::SeqCst);
    }

    /// Whether the read task is running (`zp_read_task_is_running`). A closed
    /// session runs nothing.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst) && !self.closing.load(Ordering::SeqCst)
    }

    /// Start the task (`zp_start_read_task`); idempotent, as pico's is. Refused
    /// from a callback, where a callback running means the task already does.
    pub fn start(&self) -> Result<(), CalledFromReadTask> {
        if self.in_callback() {
            return Err(CalledFromReadTask);
        }
        self.running.store(true, Ordering::SeqCst);
        self.wake_all();
        Ok(())
    }

    /// Stop the task (`zp_stop_read_task`); idempotent, as pico's is. Returns when
    /// EVERY gated future of the session has parked, so no callback is running on any
    /// thread and none will until the task is started (see the type's documentation).
    /// Refused from a callback, which would be waiting for itself.
    pub fn stop(&self) -> Result<(), CalledFromReadTask> {
        if self.in_callback() {
            return Err(CalledFromReadTask);
        }
        // The epoch first, then the flag: a task that sees the flag sees an epoch at
        // least this one, which is what it acknowledges.
        let epoch = self.stop_epoch.fetch_add(1, Ordering::SeqCst) + 1;
        self.running.store(false, Ordering::SeqCst);
        self.wake_tasks();
        self.wait_until_parked(epoch);
        Ok(())
    }

    /// Make every gated future look at the gate, even one that is idle.
    fn wake_tasks(&self) {
        let wakers: Vec<Waker> = match self.tasks.lock() {
            Ok(tasks) => tasks
                .slots
                .values()
                .filter_map(|slot| slot.waker.clone())
                .collect(),
            Err(_) => return,
        };
        for waker in wakers {
            waker.wake();
        }
    }

    /// Wait until every gated future has parked for stop number `epoch`, or no longer
    /// can (the session is closing, or the future is gone), or someone has started the
    /// task again meanwhile. A gate with no future that has ever been polled, or none
    /// left, has nothing to wait for.
    fn wait_until_parked(&self, epoch: u64) {
        loop {
            {
                let Ok(tasks) = self.tasks.lock() else {
                    return;
                };
                let all_parked = tasks.slots.values().all(|slot| slot.parked_for >= epoch);
                if all_parked
                    || self.closing.load(Ordering::SeqCst)
                    || self.running.load(Ordering::SeqCst)
                {
                    return;
                }
                // Timed, so that a wake-up that raced the checks above is noticed.
                let waited = self.parked.wait_timeout(tasks, Duration::from_millis(50));
                if waited.is_err() {
                    return;
                }
            }
            // A task that registered, or went idle, since the last wake is asked again.
            self.wake_tasks();
        }
    }

    /// The gated future `id` is about to park because the task is stopped: say so, for
    /// the newest stop asked for.
    fn acknowledge_park(&self, id: u64) {
        let epoch = self.stop_epoch.load(Ordering::SeqCst);
        if let Ok(mut tasks) = self.tasks.lock() {
            if let Some(slot) = tasks.slots.get_mut(&id) {
                if slot.parked_for < epoch {
                    slot.parked_for = epoch;
                }
            }
        }
        self.parked.notify_all();
    }

    /// Register the gated future on its first poll (`registered` holds its id from then
    /// on) and keep its waker for a stop.
    fn note_poll(&self, registered: &mut Option<u64>, waker: &Waker) -> Option<u64> {
        let mut tasks = self.tasks.lock().ok()?;
        let id = match *registered {
            Some(id) => id,
            None => {
                let id = tasks.next;
                tasks.next += 1;
                tasks.slots.insert(
                    id,
                    TaskSlot {
                        waker: None,
                        parked_for: 0,
                    },
                );
                *registered = Some(id);
                id
            }
        };
        if let Some(slot) = tasks.slots.get_mut(&id) {
            if !slot
                .waker
                .as_ref()
                .is_some_and(|known| known.will_wake(waker))
            {
                slot.waker = Some(waker.clone());
            }
        }
        Some(id)
    }

    /// The gated future `id` is gone: a stop has nobody left to wait for in its place.
    fn task_ended(&self, id: u64) {
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.slots.remove(&id);
        }
        self.parked.notify_all();
    }

    /// The session is closing: everything passes, so the drive can unwind.
    fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.wake_all();
        self.parked.notify_all();
    }

    /// Whether a face, or the accept loop, may read.
    fn faces_may_run(&self) -> bool {
        self.running.load(Ordering::SeqCst) || self.closing.load(Ordering::SeqCst)
    }

    /// Whether the session's top-level future may be polled.
    fn drive_may_run(&self) -> bool {
        !self.opened.load(Ordering::SeqCst) || self.faces_may_run()
    }

    fn park(&self, waker: &Waker) {
        if let Ok(mut parked) = self.wakers.lock() {
            if !parked.iter().any(|w| w.will_wake(waker)) {
                parked.push(waker.clone());
            }
        }
    }

    fn wake_all(&self) {
        let parked = match self.wakers.lock() {
            Ok(mut parked) => std::mem::take(&mut *parked),
            Err(_) => return,
        };
        for waker in parked {
            waker.wake();
        }
    }

    /// Wait until the task runs (or the session closes). A face calls this right
    /// after its open, and the listen role before its accept loop.
    async fn wait_running(&self) {
        std::future::poll_fn(|cx| {
            if self.faces_may_run() {
                return Poll::Ready(());
            }
            self.park(cx.waker());
            // Re-checked after the waker is published, so a start that landed
            // between the check and the park is not lost.
            if self.faces_may_run() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// Announce the open to the caller: arm the gate, then report success. The
    /// order is the point (see [`Self::mark_opened`]). `true` when the caller is
    /// gone.
    fn announce_open(&self, tx: &mpsc::Sender<bool>) -> bool {
        self.mark_opened();
        tx.send(true).is_err()
    }
}

/// The session's top-level future, polled only while its read task may run.
///
/// A future that is not polled reads no socket, fires no timer and runs none of
/// the local tasks it owns, which is exactly a stopped executor. Its writers are
/// spawned tasks on the runtime and keep running, as a pico `z_put` writes on the
/// caller's thread whether or not the executor does.
///
/// A session has several: the top-level drive, and each face that is a task of its own
/// ([`GateFaces`]). Each is registered in the gate by its first poll, and a stop waits for
/// every one of them to park.
struct Pausable<F> {
    gate: Arc<ReadGate>,
    inner: Pin<Box<F>>,
    /// This future's place in the gate, taken by its first poll.
    registered: Option<u64>,
}

impl<F> Pausable<F> {
    fn new(gate: Arc<ReadGate>, inner: F) -> Self {
        Self {
            gate,
            inner: Box::pin(inner),
            registered: None,
        }
    }
}

/// Marks the calling thread as inside a poll of a gate's future for as long as it lives,
/// which is what [`ReadGate::in_callback`] reads. Dropped on unwind too, so a panic in a
/// callback does not leave the thread marked.
struct PollingGuard;

impl PollingGuard {
    fn enter(gate: &ReadGate) -> Self {
        POLLING.with(|polling| polling.borrow_mut().push(gate as *const ReadGate as usize));
        PollingGuard
    }
}

impl Drop for PollingGuard {
    fn drop(&mut self) {
        POLLING.with(|polling| {
            polling.borrow_mut().pop();
        });
    }
}

impl<F: Future> Future for Pausable<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        let id = this.gate.note_poll(&mut this.registered, cx.waker());
        if !this.gate.drive_may_run() {
            this.gate.park(cx.waker());
            if !this.gate.drive_may_run() {
                // Parked: the inner future is not polled again until a start, so
                // no callback of the session is running on its account. A stop
                // waits for every future of the session to be here.
                if let Some(id) = id {
                    this.gate.acknowledge_park(id);
                }
                return Poll::Pending;
            }
        }
        let _polling = PollingGuard::enter(&this.gate);
        this.inner.as_mut().poll(cx)
    }
}

impl<F> Drop for Pausable<F> {
    fn drop(&mut self) {
        if let Some(id) = self.registered {
            self.gate.task_ended(id);
        }
    }
}

/// Spawn `future` on the session's runtime as a task of its own, gated like the top-level
/// drive: it is polled only while the read task may run, and a stop waits for it.
///
/// What a face that is not driven by the accept loop (a dialled endpoint's leg) uses to be a
/// task of its own and not a share of the drive thread.
fn spawn_gated<F>(gate: &Arc<ReadGate>, future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(Pausable::new(gate.clone(), future))
}

/// Spawn the leg of one endpoint (its dial, its re-dials and its face), where the session's
/// [`FaceDrive`] puts it: a local task of the drive thread for [`FaceDrive::Serial`], a task
/// of the runtime for [`FaceDrive::PerFace`], whose face is then moved to a thread of its own
/// by [`drive_face_on`] and which is otherwise idle (it dials, and waits).
///
/// Called on the drive thread's `LocalSet`, which `Serial` needs.
fn spawn_leg<F>(gate: &Arc<ReadGate>, future: F) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    match gate.face_drive() {
        FaceDrive::Serial => tokio::task::spawn_local(future),
        FaceDrive::PerFace => spawn_gated(gate, future),
    }
}

/// What a face's thread reports back to the task that waits for it.
enum OwnThreadEnd<T> {
    /// The future ran to its end.
    Done(T),
    /// The thread could not run it (no runtime could be built there): the waiter runs it itself.
    Inline,
}

/// What stops a face's thread when the task waiting for it goes away, and then waits for it.
///
/// The wait is what `z_close` rests on: the callbacks of a face run on this thread, and the C
/// `drop(context)` that follows a close must not race one. It is skipped when the thread being
/// dropped from is the face's own (a callback that closes its own session cannot wait for
/// itself).
struct OwnThreadGuard {
    cancel: Arc<Notify>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for OwnThreadGuard {
    fn drop(&mut self) {
        self.cancel.notify_one();
        if let Some(thread) = self.thread.take() {
            if thread.thread().id() != std::thread::current().id() {
                let _ = thread.join();
            }
        }
    }
}

/// Run `future` on a thread of its own, polled only while the read task may run ([`Pausable`]),
/// and hand its output to whoever awaits the result.
///
/// This is what makes a face independent of every other: the face's callbacks run on this
/// thread, so a callback that blocks stops this face and nothing else. A pool of workers
/// cannot promise that. Measured on a session with two faces: the drive of both landed on one
/// worker, and the first callback to block held the second face for as long as it blocked, with
/// four workers as with two.
///
/// The thread has a runtime of its own with a clock and no reactor: the face's socket belongs to
/// the session's runtime, whose workers wake this thread when it is readable.
///
/// Dropping the result before it is ready cancels the future (it is dropped on its own thread)
/// and waits for the thread. If no thread can be had the future runs as a task of the runtime
/// instead, which is a worse place for it and not a failure.
fn run_on_own_thread<F>(
    gate: Arc<ReadGate>,
    future: F,
) -> Pin<Box<dyn Future<Output = F::Output> + Send>>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    // Handed to the thread through a slot, so that when no thread starts the future is still
    // here to be run another way.
    let slot = Arc::new(StdMutex::new(Some(future)));
    let cancel = Arc::new(Notify::new());
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<OwnThreadEnd<F::Output>>();
    let started = std::thread::Builder::new()
        .name("wz-capi-face".to_owned())
        .stack_size(DRIVE_THREAD_STACK_BYTES)
        .spawn({
            let slot = slot.clone();
            let cancel = cancel.clone();
            let gate = gate.clone();
            move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => {
                        let _ = done_tx.send(OwnThreadEnd::Inline);
                        return;
                    }
                };
                let Some(future) = slot.lock().ok().and_then(|mut slot| slot.take()) else {
                    return;
                };
                let end = rt.block_on(async {
                    tokio::select! {
                        output = Pausable::new(gate, future) => Some(output),
                        _ = cancel.notified() => None,
                    }
                });
                if let Some(output) = end {
                    let _ = done_tx.send(OwnThreadEnd::Done(output));
                }
            }
        });
    let thread = match started {
        Ok(thread) => thread,
        Err(_) => {
            let future = slot.lock().ok().and_then(|mut slot| slot.take());
            return match future {
                Some(future) => Box::pin(Pausable::new(gate, future)),
                None => Box::pin(std::future::pending()),
            };
        }
    };
    let guard = OwnThreadGuard {
        cancel,
        thread: Some(thread),
    };
    Box::pin(async move {
        let _guard = guard;
        match done_rx.await {
            Ok(OwnThreadEnd::Done(output)) => output,
            Ok(OwnThreadEnd::Inline) => {
                let future = slot.lock().ok().and_then(|mut slot| slot.take());
                match future {
                    Some(future) => Pausable::new(gate, future).await,
                    None => std::future::pending().await,
                }
            }
            // The thread ended with no output and was not cancelled: the face's drive panicked.
            // The panic is raised again here, where the task that spawned this one reads it as
            // the drive of that face having failed.
            Err(_) => panic!("the thread of a face ended without a result"),
        }
    })
}

/// [`drive_face`], where the session's [`FaceDrive`] runs it: inline for `Serial`, on a thread
/// of its own for `PerFace`.
async fn drive_face_on(
    face: u64,
    session: OpenedSession,
    shared: Arc<SharedSession>,
    closing: impl Future<Output = ()> + Send + 'static,
    on_up: impl FnOnce() + Send + 'static,
    gate: Arc<ReadGate>,
) -> bool {
    match gate.face_drive() {
        FaceDrive::Serial => drive_face(face, session, &shared, closing, on_up, &gate).await,
        FaceDrive::PerFace => {
            let own = gate.clone();
            run_on_own_thread(own, async move {
                drive_face(face, session, &shared, closing, on_up, &gate).await
            })
            .await
        }
    }
}

// --- per-session state -----------------------------------------------------

/// The C session handle: the face registry + subscription SSOT the C thread
/// declares and publishes through, plus the drive thread's shutdown signal and
/// join handle.
pub struct SessionState {
    pub shared: Arc<SharedSession>,
    /// This session's own zid, zero-padded to 16 bytes; the INIT carries the same id with
    /// the trailing zero bytes trimmed (see [`session_zids`]).
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
    /// R2957 — per-session state that belongs to ONE C ABI and not to this
    /// ABI-neutral core: zenoh-c's session owns a shared-memory provider
    /// (upstream's `Runtime::get_shm_provider`), and zenoh-pico has no shared
    /// memory at all. Set once, by the shim, right after the open; see
    /// [`Self::set_abi_extension`].
    abi_extension: std::sync::OnceLock<Box<dyn std::any::Any + Send + Sync>>,
    /// Whether the session's drive is being run: pico's background executor. See
    /// [`ReadGate`].
    read_gate: Arc<ReadGate>,
}

impl SessionState {
    /// Start the read task (pico `zp_start_read_task`); idempotent. Refused from
    /// inside one of the session's own callbacks.
    pub fn start_read_task(&self) -> Result<(), CalledFromReadTask> {
        self.read_gate.start()
    }

    /// Stop the read task (pico `zp_stop_read_task`); idempotent, and it returns
    /// only once no callback is running. While it is stopped the session reads
    /// nothing and sends no keep-alive, and what arrives waits in the socket.
    /// Refused from inside one of the session's own callbacks.
    pub fn stop_read_task(&self) -> Result<(), CalledFromReadTask> {
        self.read_gate.stop()
    }

    /// Whether the read task is running (pico `zp_read_task_is_running`).
    pub fn read_task_is_running(&self) -> bool {
        self.read_gate.is_running()
    }

    /// Attach this ABI's per-session state. Once: a second call is refused and
    /// returns the value it was handed, so a shim cannot silently replace
    /// state a live handle already reads.
    pub fn set_abi_extension<E: std::any::Any + Send + Sync>(&self, ext: E) -> Result<(), E> {
        self.abi_extension
            .set(Box::new(ext))
            .map_err(|boxed| *boxed.downcast::<E>().expect("the value just boxed"))
    }

    /// This ABI's per-session state, if the shim attached one of type `E`.
    pub fn abi_extension<E: std::any::Any>(&self) -> Option<&E> {
        self.abi_extension.get()?.downcast_ref::<E>()
    }

    /// This session's own zid (pico `z_info_zid`). Always the id the INIT
    /// carried, padded — see the field.
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
        // The gate is opened BEFORE the join, and that is load-bearing: a session
        // whose read task is stopped is not being polled at all, so neither the
        // latch above nor the notify below could reach the shutdown future inside
        // it, and the join would wait for a thread that is waiting for this call.
        self.read_gate.close();
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
/// The override is [`ConfiguredZid`]: a caller whose config states an id opens on
/// that one and this is what it does NOT call. The zenoh-c ABI reads its `id`
/// key; the zenoh-pico ABI's `Z_CONFIG_SESSION_ZID_KEY` still is follow-up
/// surface, so pico's default path is this.
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
    // An id of all zero bytes names nothing (zenoh refuses it), as a failed source does.
    if zid.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(zid)
}

/// The two forms of the id a session stands on, from ONE choice: what
/// `z_info_zid` reports (sixteen bytes) and what the INIT carries.
///
/// The first is the id zero-padded to sixteen bytes and the second the trimmed form of
/// it, and it is the trimmed one that goes on the wire: zenoh writes an id as the bytes up
/// to its last non-zero one, so `c11e47c11e49` is six on the wire and a peer that logs the
/// session's id reads it as such. That holds for a minted id as much as for a configured
/// one: a minted id whose last byte is zero (one in 256) is fifteen bytes on the wire, and
/// the sixteen it used to put there made a node found through the routing graph, which
/// holds the trimmed form, unequal to the same node met on a link. `None` only when the
/// entropy source fails on the default path, which fails the open.
///
/// A free function and not a block in [`open_blocking`] so that the choice can be
/// held by a test that has no peer to look at the INIT.
fn session_zids(configured: Option<ConfiguredZid>) -> Option<([u8; ZID_LENGTH], Vec<u8>)> {
    match configured {
        Some(configured) => Some((configured.padded(), configured.wire().to_vec())),
        None => Some(minted_zids(fresh_zid()?)),
    }
}

/// The two forms of an id the session minted for itself, see [`session_zids`].
fn minted_zids(minted: [u8; ZID_LENGTH]) -> ([u8; ZID_LENGTH], Vec<u8>) {
    (
        minted,
        wz_runtime_tokio::zid_hex::canonical_zid(&minted).to_vec(),
    )
}

/// Whether the node a link opened to is the one that was dialled. The expected id comes from
/// the routing graph, which holds an id trimmed; the link holds the bytes the peer sent; the
/// comparison is of the id, not of its spelling.
fn is_expected_peer(peer: Option<&[u8]>, expected: &[u8]) -> bool {
    peer.is_some_and(|peer| wz_runtime_tokio::zid_hex::same_zid(peer, expected))
}

/// The zid a config STATES for its session, checked and in the form zenoh puts
/// on the wire.
///
/// A value of this type cannot be built from text zenoh refuses, so a caller that
/// holds one has nothing left to validate and [`open_blocking`] has no invalid
/// length to report. The reading of the text is `zid_hex::zenoh_hex_to_zid`
/// and nothing here restates it: a lowercase hex `u128`, the id's little-endian
/// bytes with the trailing zeros trimmed, no leading `0`, at most sixteen bytes.
/// That rule was measured against the pinned zenohd and is the one the command
/// line and the `--zid` parse already use, so a config's `id` and a flag's value
/// name the same node.
///
/// # Two forms of one id
///
/// The WIRE form is what an INIT carries: one to sixteen bytes, trailing zeros
/// trimmed, so `c11e47c11e49` is six bytes. The STATE form is what `z_info_zid`
/// reports: sixteen bytes, the same id zero-padded. Both come from this one
/// value, so the session cannot say one identity on the wire and another to its
/// own caller, which is the property the random path gets from minting once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredZid {
    wire: Vec<u8>,
}

impl ConfiguredZid {
    /// The id a config's text names, or `None` for text zenoh refuses.
    pub fn from_zenoh_text(text: &str) -> Option<Self> {
        let wire = wz_runtime_tokio::zid_hex::zenoh_hex_to_zid(text)?;
        // `zenoh_hex_to_zid` answers one to sixteen bytes for every text it
        // accepts, and the constructor is the one place that is relied on.
        if wire.is_empty() || wire.len() > ZID_LENGTH {
            return None;
        }
        Some(Self { wire })
    }

    /// The form an INIT carries.
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// The form `z_info_zid` reports: sixteen bytes, zero-padded.
    fn padded(&self) -> [u8; ZID_LENGTH] {
        let mut zid = [0u8; ZID_LENGTH];
        zid[..self.wire.len()].copy_from_slice(&self.wire);
        zid
    }
}

/// What a session's links are told about transmitting: the queue model the calling ABI stands
/// for, and the batch size the session ADVERTISES in its InitSyn or InitAck.
///
/// The batch size is the half of the negotiation this node controls: the size both ends settle on
/// is the smaller of the two advertised, and a frame the writer builds past it is fragmented
/// (`emit_frame_or_fragments`). It was a constant here, so a config that stated
/// `transport/link/tx/batch_size` was read and then not put on the wire, and a session could not
/// be made to negotiate anything below 65535. Travelling WITH the queue model because both are
/// read at the same place, `init_params` (not linked: it is private), by every role that mints
/// parameters.
#[derive(Clone, Copy, Debug)]
pub struct LinkTx {
    /// The transmit model: see [`OpenStance::tx_queue`].
    pub queue: TxQueueConf,
    /// The batch size advertised, in bytes.
    pub batch_size: u16,
}

/// The batch size a session advertises when its config states none: zenoh's own default
/// (`transport/link/tx/batch_size`, 65535).
pub const DEFAULT_BATCH_SIZE: u16 = 65535;

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
    link_tx: LinkTx,
) -> Result<SessionInitParams, EntropyUnavailable> {
    Ok(SessionInitParams {
        version: 0x09,
        whatami,
        zid,
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: link_tx.batch_size,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        tx_queue: link_tx.queue,
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
    /// This session's own zid in the form the INIT carries: fixed on the calling
    /// thread, from the same value as [`SessionState::zid`], so the two cannot
    /// disagree. Sixteen random bytes on the default path; the trimmed bytes of a
    /// [`ConfiguredZid`] when the config stated one.
    zid: Vec<u8>,
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
    link_tx: LinkTx,
    /// The capabilities the calling ABI's session offers, dialled and accepted
    /// alike. See [`open_blocking`].
    offer: SessionOffer,
    /// Whether the session's drive is being run. Shared with [`SessionState`],
    /// which is what a C program starts and stops it through.
    gate: Arc<ReadGate>,
    /// R3070 -- what the session does with multicast scouting, when it scouts at all: see
    /// [`OpenStance::scouting`].
    scouting: Option<ScoutingPlan>,
    /// R3074 -- where the nodes a peer is told of are posted to be dialled, and the end the
    /// connector reads them from. Scouting posts the nodes a Hello names and the gossip plane
    /// (which holds a sender of its own, in the registry) posts the nodes a list names, so one
    /// task dials both and the two cannot dial the same node twice.
    dials: (DialIntentSender, DialIntentReceiver),
    /// Whether the session gossips, as [`OpenStance::gossip`] says and its role allows.
    gossiping: bool,
    /// R3076 -- what an endpoint of `listen` that cannot be bound does to the open, and R3089 --
    /// how long and how often it is tried; see [`OpenStance::listen_phase`].
    listen_phase: ListenPhase,
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
/// the open does not wait for its peer, in which case it unblocks first.
///
/// R3067 -- `listen` is the session's own listener, for a session that also
/// dials. A peer or router accepts on it beside its dials; a client binds it
/// and serves nothing on it (see where the client branch holds it), which is
/// what the real library does with one stated beside a `connect`.
async fn drive_dial(
    endpoints: Vec<String>,
    listen: Vec<String>,
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
        link_tx,
        offer,
        gate,
        scouting,
        dials,
        gossiping,
        listen_phase,
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
    let params = match init_params(whatami, zid.to_vec(), link_tx) {
        Ok(p) => p,
        Err(_) => {
            let _ = tx.send(false);
            return;
        }
    };
    let dialer = Arc::new(Dialer {
        dial_cfgs,
        params,
        offer,
        clock,
        tls: tls.clone(),
    });
    // R2950 — the two ROLES connect differently upstream, and each is built
    // here as upstream builds it. A client connects through
    // `connect_peers_single_link` and holds ONE session ("the client mode only
    // allows connecting to a single endpoint", `DEFAULT_CONFIG.json5`); a peer
    // or router through `connect_peers_multiply_links`, which connects to EVERY
    // endpoint it can, each with its own failure policy. See [`drive_peer`].
    //
    // R3067 -- the listener, when the session has one, is bound BEFORE the first
    // dial and for either role, as upstream's `start_client` and `start_peer`
    // both bind their listeners before they connect; a bind that fails fails
    // the open, because the caller asked for a listener.
    //
    // R3076 -- every endpoint the config states, in its order, under `listen/exit_on_failure`.
    // R3089 -- and under the budget and the retry of `listen/timeout_ms` and `listen/retry`.
    let BoundListeners { legs: listen, late } =
        match bind_listeners(&listen, listen_phase, &tls, &zid, link_tx, offer, clock).await {
            Some(bound) => bound,
            None => {
                let _ = tx.send(false);
                return;
            }
        };
    // R3074 -- where gossip tells a neighbour this node can be dialled: the locators the
    // listeners ACTUALLY got, without the loopback ones, as upstream's `get_locators_noloopback`
    // lists them. Set before the first face can come up, so the first list a neighbour is sent
    // carries them. A node with no listener tells none, and is introduced to nobody as a node to
    // dial, though it dials what it is told of.
    let listeners: Vec<&BoundListener> = listen.iter().map(|leg| &leg.listening.listener).collect();
    // R3089 -- and the listeners that bind later add theirs to this list when they do.
    let late = if gossiping {
        let bound_before = Advertised::of_all(&listeners).remote;
        shared.set_gossip_locators(bound_before.clone());
        late.gossiping(bound_before)
    } else {
        late
    };
    // R3071 -- bound once its listener is, for either role: a client's bound-and-unserved
    // listener is advertised too (measured: a real client with a listener answers a Scout naming
    // it, and one with none answers with no locators at all). When it STARTS answering is the
    // role's: a peer or router's after its connect walk (R3125), a client's after it connects.
    let responder = match bound_responder(
        scouting.as_ref(),
        whatami,
        &zid,
        &listeners,
        late.locators(),
    )
    .await
    {
        Ok(responder) => responder,
        Err(()) => {
            let _ = tx.send(false);
            return;
        }
    };
    if whatami != WhatAmI::Client {
        // R3070 -- a peer or router that scouts also dials what it finds, beside the endpoints
        // it was told, as upstream's `start_peer` starts its scouting after its connects.
        let scouting = scouting.filter(ScoutingPlan::scouts);
        // R3074 -- and what it is told of, by a Hello or by a list, is dialled by one task.
        // A node that neither scouts nor gossips is told of nobody and needs none.
        let dials = (scouting.is_some() || gossiping).then_some(dials);
        // R3125 -- and findable only then. The responder is bound and held here, and started by
        // `drive_peer` once its connect walk has ended: upstream spawns it in `start_scout`, which
        // `start_peer` and `start_router` both run after `connect_peers`. Started at the bind, as
        // it was, a peer whose walk is one attempt that the open waits for answered a Scout in
        // the middle of that attempt.
        let router_hold = (whatami == WhatAmI::Router).then_some(phase.router_hold);
        drive_peer(
            endpoints,
            listen,
            late,
            scouting,
            zid,
            dials,
            responder,
            router_hold,
            phase,
            dialer,
            shared,
            tx,
            shutdown,
            stop,
            gate,
        )
        .await;
        return;
    }
    // A client's listener is BOUND and serves nobody. Measured on the real
    // library: a client stated with `listen` and `connect` opens, its port is
    // taken, and a peer that dials it reaches nothing and is reached by
    // nothing (the sample each side publishes never arrives at the other) -- the
    // client's routing owns exactly one face, the link it dialled
    // (`zenoh/src/net/routing/hat/client/mod.rs` @
    // `debug_assert_eq!(self.owned_faces(ctx.tables).count(), 1);`). So the
    // listener is held for the session's life and no accept loop runs on it.
    let _bound_and_unserved = listen;
    // R3070 -- a client with no endpoint of its own scouts for the first node it can open a
    // session to (upstream's `connect_first`); one with an endpoint dials only that.
    let scouting = scouting
        .filter(ScoutingPlan::scouts)
        .filter(|_| endpoints.is_empty())
        .map(|plan| (plan, zid.clone()));
    // R3071 -- and a client that SEARCHES answers no Scout until it has connected, where one that
    // was told its endpoint answers from the start (see [`Responder`]).
    let (_findable, after_connecting) = if scouting.is_some() {
        (None, responder)
    } else {
        (responder.map(Responder::start), None)
    };
    // R3089 -- a listener of a client that is bound after the open is held as the others are.
    tokio::select! {
        _ = drive_client(
            endpoints,
            scheduled,
            scouting,
            after_connecting,
            phase,
            dialer,
            shared,
            tx,
            shutdown,
            stop,
            gate,
        ) => {}
        _ = late.hold() => {}
    }
}

/// R3071 -- bind the responder that makes the session FINDABLE when its plan says it answers a
/// Scout: the group joined, ready to answer with the zid, the role and where the session's
/// listener is reached (nothing, for a session with none). `Ok(None)` for a session that does
/// not scout at all or does not answer.
///
/// Bound here and started by the caller, because a client that searches starts answering only
/// once it has connected (see [`Responder`]). The started responder is held by the role's drive
/// for the session's life and dropped with it. A bind that fails is an open failure, as the
/// listener's is: a session that was told to be findable is never silently not.
async fn bound_responder(
    plan: Option<&ScoutingPlan>,
    whatami: WhatAmI,
    zid: &[u8],
    listeners: &[&BoundListener],
    late: LateLocators,
) -> Result<Option<Responder>, ()> {
    let Some(plan) = plan else {
        return Ok(None);
    };
    bind_responder(plan, whatami, zid, Advertised::of_all(listeners), late)
        .await
        .map_err(|_| ())
}

/// A client with nothing to dial: scout the group and open a session to the first node that
/// answers and can be opened to, within the plan's timeout.
///
/// Upstream's `connect_first`: every Hello with a locator is tried (`connect`), the first node
/// that connects ends the search, and a search that outlives `scouting/timeout` fails the open.
/// The scouting stops when this returns, as upstream's does: a client does not autoconnect to a
/// second node.
async fn connect_first(
    plan: &ScoutingPlan,
    zid: &[u8],
    dialer: &Dialer,
) -> Result<OpenedSession, ()> {
    // A bind that fails fails the open, as upstream's `connect_first` is reached only after its
    // multicast bind succeeded.
    let link = ScoutLink::bind(plan).await.map_err(|_| ())?;
    let (intents_tx, mut intents) = tokio::sync::mpsc::unbounded_channel();
    let scouting = link.autoconnect(plan, zid, &intents_tx);
    tokio::pin!(scouting);
    let deadline = tokio::time::sleep(plan.timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            Some(intent) = intents.recv() => {
                if let Some(session) = dial_scouted(dialer, &intent).await {
                    return Ok(session);
                }
            }
            _ = &mut scouting => return Err(()),
            _ = &mut deadline => return Err(()),
        }
    }
}

/// Open a session to the node `intent` names, through the first of its locators that opens to
/// that node, as upstream's `connect` walks them.
async fn dial_scouted(dialer: &Dialer, intent: &DialIntent) -> Option<OpenedSession> {
    for locator in &intent.locators {
        if let Ok(session) = dialer.open_scouted(locator, &intent.zid).await {
            return Some(session);
        }
    }
    None
}

/// A client's drive: connect to ONE endpoint of the list, hold the one session,
/// and re-dial it when it is lost.
///
/// R3067 -- the body `drive_dial` held inline; it moved here unchanged when the
/// dial gained a listener to bind before it.
#[allow(clippy::too_many_arguments)]
async fn drive_client(
    endpoints: Vec<String>,
    scheduled: Vec<(String, RetryPolicy)>,
    scouting: Option<(ScoutingPlan, Vec<u8>)>,
    answer_after_connecting: Option<Responder>,
    phase: DialPhase,
    dialer: Arc<Dialer>,
    shared: Arc<SharedSession>,
    tx: mpsc::Sender<bool>,
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
    gate: Arc<ReadGate>,
) {
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
    //
    // R3070 -- with nothing configured to dial and scouting on, the first connection is a
    // scouted one instead (`connect_first`), and nothing is re-dialled behind it: `rescheduled`
    // is empty because `endpoints` is, so a lost link ends the session as it would on the real
    // library, which scouts for no second node.
    let first = match &scouting {
        Some((plan, zid)) => connect_first(plan, zid, &dialer)
            .await
            .map_err(|e| log_open_failure("scouted connect", &e)),
        None => drive_connect_phase(phase.policy.budget, &scheduled, &attempt)
            .await
            .map_err(|e| log_open_failure(&format!("connect to {endpoints:?}"), &e)),
    };
    let mut session = match first {
        Ok(opened) => opened,
        Err(()) => {
            let _ = tx.send(false);
            return;
        }
    };
    // R3071 -- connected, so findable, as upstream's client spawns its responder after
    // `connect_first`. Held until the session ends.
    let _findable = answer_after_connecting.map(Responder::start);
    let mut released = false;

    loop {
        // A client's session has exactly one peer, so it occupies the single
        // `DIAL_FACE_ID` slot; from here the C surface is role-agnostic (it fans
        // over whatever faces the registry holds). A re-dialled session lands in
        // the same slot, and `face_up` replays the declarations onto it.
        //
        // R311y557 — the LOCAL PLANE's drain is an arm of THIS select, not a
        // `tokio::spawn`. Both placements keep the C application thread out of
        // the C callbacks, which an ABI that drains its plane on the drive task
        // (zenoh-pico's) needs; only this one also keeps the plane's deliveries
        // from overlapping the face's, because a `select!` polls its arms on ONE
        // task while the per-session runtime has two worker threads a spawned
        // task could land on. (R3069: zenoh-c's plane drains on the calling
        // thread, and this arm drains only what a staging path left behind.)
        let abandoned = Arc::new(AtomicBool::new(false));
        tokio::select! {
            _ = drive_face_on(
                DIAL_FACE_ID,
                session,
                shared.clone(),
                shutdown_future(shutdown.clone(), stop.clone()),
                {
                    let abandoned = abandoned.clone();
                    let gate = gate.clone();
                    let tx = tx.clone();
                    move || {
                        if !released {
                            abandoned.store(gate.announce_open(&tx), Ordering::SeqCst);
                        }
                    }
                },
                gate.clone(),
            ) => {}
            _ = shared.drive_local_plane() => {}
        }
        if abandoned.load(Ordering::SeqCst) {
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
///
/// R3067 -- `false` when the registry did not admit the face because the node it
/// links to is already held by another: the link is closed and `on_up` has not
/// run. `true` when the face was held and has since ended.
async fn drive_face(
    face: u64,
    session: OpenedSession,
    shared: &Arc<SharedSession>,
    closing: impl std::future::Future<Output = ()>,
    on_up: impl FnOnce(),
    gate: &ReadGate,
) -> bool {
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
    // R3067 -- a node this session already has a face to is not given a second
    // one ([`SharedSession::face_up`]). The link is closed the way every face's
    // is, through the drain, and `on_up` does not run: the open was not
    // released by a face that is not held.
    if !shared.face_up(face, &actions) {
        OpenedSession {
            engine,
            actions,
            inbound,
            writer_handle,
            clock,
        }
        .drain_to_close()
        .await;
        return false;
    }
    on_up();
    // A session opened without its read task reads nothing until it is started
    // (see [`ReadGate`]). The open above is done and was announced; this is the
    // first frame the face would read, so this is where it waits. `closing` ends
    // the wait too: a peer whose open failed closes its faces through it, and a
    // face held here must not outlive that.
    let mut closing = std::pin::pin!(closing);
    let closed_while_held = tokio::select! {
        _ = gate.wait_running() => false,
        _ = closing.as_mut() => true,
    };

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
    //
    // Skipped when the session closed while the face was held above: a face that
    // was told to go must not read one frame on its way out.
    if !closed_while_held {
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
            _ = closing.as_mut() => {}
        }
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
    true
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
/// (see [`DIAL_FACE_ID`]). The faces run on a `LocalSet`, because a session's
/// drive futures are not `Send`, and on this task, so none of them can outlive
/// the session's runtime.
///
/// R3067 -- `listen` is the session's own listener, when it has one: a peer
/// that is both a listener and a dialler, which zenoh starts when a config
/// states `listen` and `connect` together. Upstream binds the listeners first
/// and connects after, and so does this: the accept loop is a local task beside
/// the dial faces, running from before the first dial, so a peer that dials
/// this one while it is still walking its own connect list is accepted.
///
/// R3070 -- `scouting` is the plan of a peer that also looks for others on the multicast group:
/// scouting starts after the connects, as upstream's `start_peer` runs `start_scout` after
/// `connect_peers`, a group that cannot be joined fails the open, and the open's start window
/// waits for the first scouted connection as well as for the endpoints it was told.
///
/// R3074 -- `dials` is the channel the nodes this peer is told of are posted on, and `zid` is
/// its own wire zid, which a node told of must not be. It is `Some` for a peer that scouts or
/// gossips, and one connector reads it for both, so a node scouting and gossip both name is
/// dialled once.
///
/// R3125 -- `responder` is the answer to a Scout, bound and not yet started: it starts here, once
/// the walk has ended and has not failed, where upstream's `start_scout` spawns it. `router_hold`
/// is `Some` for a router, whose open is held for `scouting/delay` in full after that, where a
/// peer's ends as soon as its start conditions are met.
#[allow(clippy::too_many_arguments)]
async fn drive_peer(
    endpoints: Vec<String>,
    listen: Vec<ListenLeg>,
    late: LateBinds,
    scouting: Option<ScoutingPlan>,
    zid: Vec<u8>,
    dials: Option<(DialIntentSender, DialIntentReceiver)>,
    responder: Option<Responder>,
    router_hold: Option<std::time::Duration>,
    phase: DialPhase,
    dialer: Arc<Dialer>,
    shared: Arc<SharedSession>,
    tx: mpsc::Sender<bool>,
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
    gate: Arc<ReadGate>,
) {
    let (closing_tx, closing_rx) = tokio::sync::watch::channel(false);
    let window = Arc::new(StartWindow::default());
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut faces: Vec<tokio::task::JoinHandle<()>> = Vec::new();
            for leg in listen {
                faces.push(spawn_accept_leg(leg, &shared, &gate, closing_rx.clone()));
            }
            // R3089 -- and the listeners whose bind goes on in the background, each served from
            // the moment it binds.
            faces.extend(late.spawn(&shared, &gate, &closing_rx));
            let deadline = phase
                .policy
                .budget
                .deadline()
                .map(|d| tokio::time::Instant::now() + d);
            let mut failed = false;
            let mut registered_faces: Vec<tokio::sync::oneshot::Receiver<()>> = Vec::new();
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
                    gate: gate.clone(),
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
                                let (owed, registered) = FaceOwed::awaited_by_the_walk();
                                registered_faces.push(registered);
                                faces.push(spawn_leg(&gate, leg.run(Some(session), None, owed)))
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
                                let (owed, registered) = FaceOwed::awaited_by_the_walk();
                                registered_faces.push(registered);
                                faces.push(spawn_leg(&gate, leg.run(Some(session), None, owed)))
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
                        faces.push(spawn_leg(
                            &gate,
                            leg.run(None, Some(schedule), FaceOwed::none()),
                        ));
                    }
                }
            }
            // Every endpoint the walk connected is a face in the registry before the open
            // is released, so a caller's first call after `z_open` fans over it (see
            // [`FaceOwed`]). The faces' tasks run while this waits: they are spawned on
            // this task's own `LocalSet`.
            if !failed {
                for registered in registered_faces {
                    let _ = registered.await;
                }
            }
            // R3125 -- findable from here: the walk is over. A walk that failed leaves the
            // responder unstarted, as upstream's `connect_peers` returns its error before
            // `start_scout` runs. Held to the end of this block, which is the session's life.
            let _findable = if failed {
                None
            } else {
                responder.map(Responder::start)
            };
            if !failed {
                // The group is joined before anything is started, so a group that cannot be
                // joined fails the open with no task of this half running.
                let mut scout = None;
                if let Some(plan) = scouting {
                    match ScoutLink::bind(&plan).await {
                        Ok(link) => scout = Some((plan, link)),
                        Err(_) => failed = true,
                    }
                }
                if let (false, Some((intents_tx, intents))) = (failed, dials) {
                    // The open waits for a scouted connection only when it was told
                    // nothing to connect to: with endpoints, the window is theirs.
                    // Measured: a peer whose live endpoint connected opens in 10 ms on
                    // the real library whether or not it scouts, and one with none
                    // waits out `scouting/delay` for the first node it finds. A node that
                    // does not scout has no such window: what gossip tells it of is dialled
                    // when it is told, and the open does not wait for it.
                    let waits_for_scouted = scout.is_some() && endpoints.is_empty();
                    if waits_for_scouted {
                        window.expect_one();
                    }
                    if let Some((plan, link)) = scout {
                        let mut scout_closing = closing_rx.clone();
                        let scout_zid = zid.clone();
                        faces.push(tokio::task::spawn_local(async move {
                            tokio::select! {
                                _ = link.autoconnect(&plan, &scout_zid, &intents_tx) => {}
                                _ = scout_closing.wait_for(|c| *c) => {}
                            }
                        }));
                    }
                    faces.push(tokio::task::spawn_local(scouted_connector(ScoutedPeers {
                        configured: endpoints.clone(),
                        intents,
                        own_zid: zid,
                        first_face: DIAL_FACE_ID + endpoints.len() as u64,
                        dialer: dialer.clone(),
                        shared: shared.clone(),
                        gate: gate.clone(),
                        window: window.clone(),
                        releases_window: waits_for_scouted,
                        closing: closing_rx.clone(),
                    })));
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
            match router_hold {
                // R3125 -- a router sleeps `scouting/delay` out, whatever its connects did and
                // whether or not it scouts, as upstream's `start_router` ends.
                Some(hold) => tokio::time::sleep(hold).await,
                // The start window: the background endpoints, up to the window.
                None => {
                    if let Some(span) = phase.start_window {
                        window.wait(span).await;
                    }
                }
            }
            if gate.announce_open(&tx) {
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

/// The locator an endpoint names: the endpoint without its `#` configuration tail, as upstream's
/// `EndPoint::to_locator` drops it (`commons/zenoh-protocol/src/core/endpoint.rs` @
/// `pub const CONFIG_SEPARATOR: char = '#';`). The `?` metadata stays, so two endpoints that
/// differ in it are two locators.
fn endpoint_locator(endpoint: &str) -> &str {
    endpoint
        .split_once('#')
        .map_or(endpoint, |(locator, _)| locator)
}

/// The locators of a scouted node that scouting may dial: those that are not one of the endpoints
/// the config STATES to connect to. Upstream filters its scouted locators against the configured
/// `connect/endpoints` and ignores the node when none is left ("Already connecting to locators of
/// {zid} (connect configuration). Ignore.", `zenoh/src/net/runtime/orchestrator.rs` @
/// `.filter(|l| !configured_locators.contains(l))`), because those endpoints have a schedule of
/// their own that is already connecting to that node.
///
/// MEASURED on this tree before it had the filter: a peer that stated `connect` to a real peer
/// and scouted dialled the same node twice, the real peer admits one link per node and refused
/// the second, and when the refused one was the stated endpoint (3 runs in 30, the scouted dial
/// having answered first) the endpoint went back to its retry schedule and the open ran out
/// `scouting/delay`, 513 ms against 25. Compared as strings, as upstream compares `Locator`s, so
/// a name and the address it resolves to are two locators there and here.
fn scouted_locators_to_dial(configured: &[String], scouted: &[String]) -> Vec<String> {
    scouted
        .iter()
        .filter(|locator| {
            !configured
                .iter()
                .any(|endpoint| endpoint_locator(endpoint) == locator.as_str())
        })
        .cloned()
        .collect()
}

/// The zids of the scouted nodes being dialled right now, shared by the connector and its legs.
type DialingSet = Arc<StdMutex<std::collections::BTreeSet<Vec<u8>>>>;

/// The set under its lock. A holder that panicked left a set that is still a set, so a poisoned
/// lock is read through.
fn dialing_zids(
    set: &DialingSet,
) -> std::sync::MutexGuard<'_, std::collections::BTreeSet<Vec<u8>>> {
    set.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What the task that dials the nodes a peer's scouting finds is given.
struct ScoutedPeers {
    /// The endpoints the config states to connect to: scouting does not dial their locators.
    configured: Vec<String>,
    intents: tokio::sync::mpsc::UnboundedReceiver<DialIntent>,
    /// This node's own wire zid: its own Scout can come back through the group.
    own_zid: Vec<u8>,
    /// The first face id of the nodes found, after the ones the configured endpoints use.
    first_face: u64,
    dialer: Arc<Dialer>,
    shared: Arc<SharedSession>,
    gate: Arc<ReadGate>,
    window: Arc<StartWindow>,
    /// Whether the open is waiting on this connector: the first node it connects to releases
    /// `window`. `false` when the session has endpoints of its own, whose window it is.
    releases_window: bool,
    closing: tokio::sync::watch::Receiver<bool>,
}

/// Dial each node the session's scouting admits, on a face of its own, until the session closes.
///
/// R3070 -- upstream's `connect_peer`, which `autoconnect_all` calls for every Hello of every
/// window: a node this session already holds a face to, or is already dialling, is not dialled
/// again, and one whose face was lost is dialled the next time it answers. That is the whole of
/// the recovery for a scouted link, so a face that ends is not re-dialled here.
async fn scouted_connector(peers: ScoutedPeers) {
    let ScoutedPeers {
        configured,
        mut intents,
        own_zid,
        first_face,
        dialer,
        shared,
        gate,
        window,
        releases_window,
        mut closing,
    } = peers;
    // Shared by the legs, which are tasks of their own on the runtime's workers.
    let dialing: DialingSet = Arc::default();
    // Already "announced" when the open is not waiting: `one_connected` lowers a count that
    // `expect_one` raised, and lowering one nobody raised would wrap it.
    let announced = Arc::new(AtomicBool::new(!releases_window));
    let mut next_face = first_face;
    let mut legs: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    // Each leg waits on its own copy of the signal; the loop's own is borrowed by the wait below.
    let leg_closing = closing.clone();
    loop {
        tokio::select! {
            intent = intents.recv() => {
                let Some(mut intent) = intent else { break };
                if wz_runtime_tokio::zid_hex::same_zid(&intent.zid, &own_zid)
                    || shared.holds_peer(&intent.zid)
                    || dialing_zids(&dialing).contains(&intent.zid)
                {
                    continue;
                }
                // A node the config states an endpoint of is the endpoint's to connect to.
                intent.locators = scouted_locators_to_dial(&configured, &intent.locators);
                if intent.locators.is_empty() {
                    continue;
                }
                dialing_zids(&dialing).insert(intent.zid.clone());
                let face = next_face;
                next_face += 1;
                legs.retain(|leg| !leg.is_finished());
                legs.push(spawn_leg(&gate, scouted_leg(
                    face,
                    intent,
                    dialer.clone(),
                    shared.clone(),
                    gate.clone(),
                    window.clone(),
                    leg_closing.clone(),
                    dialing.clone(),
                    announced.clone(),
                )));
            }
            _ = closing.wait_for(|c| *c) => break,
        }
    }
    for leg in legs {
        let _ = leg.await;
    }
}

/// One scouted node's face: dial it, then drive the face until the session closes or the link
/// ends. The first scouted connection of the session releases the open's start window.
#[allow(clippy::too_many_arguments)]
async fn scouted_leg(
    face: u64,
    intent: DialIntent,
    dialer: Arc<Dialer>,
    shared: Arc<SharedSession>,
    gate: Arc<ReadGate>,
    window: Arc<StartWindow>,
    mut closing: tokio::sync::watch::Receiver<bool>,
    dialing: DialingSet,
    announced: Arc<AtomicBool>,
) {
    let mut ended = closing.clone();
    let opened = tokio::select! {
        opened = dial_scouted(&dialer, &intent) => opened,
        _ = ended.wait_for(|c| *c) => None,
    };
    dialing_zids(&dialing).remove(&intent.zid);
    let Some(session) = opened else {
        return;
    };
    // The first scouted connection releases the window, once its face is registered.
    let mut owed = FaceOwed::none();
    if !announced.swap(true, Ordering::SeqCst) {
        owed.window = Some(window);
    }
    let owed = Arc::new(StdMutex::new(owed));
    drive_face_on(
        face,
        session,
        shared,
        async move {
            let _ = closing.wait_for(|c| *c).await;
        },
        {
            let owed = owed.clone();
            move || pay(&owed)
        },
        gate,
    )
    .await;
    pay(&owed);
}

/// Pay what a leg owes the open, from wherever its face runs. Idempotent, as [`FaceOwed::pay`].
fn pay(owed: &StdMutex<FaceOwed>) {
    if let Ok(mut owed) = owed.lock() {
        owed.pay();
    }
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

/// What an open is owed by one face, paid at the one moment the face can be used: when it
/// is in the session's registry.
///
/// A connected link is not yet a face. [`drive_face`] registers it ([`SharedSession::face_up`])
/// a task later, and every C call that fans over the registry (`z_get`, a put, a declare)
/// reads it from the calling thread the instant the open returns. An open released at "the
/// link connected" therefore let a caller's first `z_get` find no face: it completed at once
/// with no query on the wire, and the peer's queryable waited for ever. MEASURED on the pico
/// ABI, roughly one hang in a hundred runs of a two-session get with sixteen running at
/// once, the registry holding zero faces when the get fanned out. Zenoh-pico adds its peer
/// inside `z_open`, so that call returns with the peer in place.
///
/// Paid by [`drive_face`]'s `on_up`, which runs after the registration, and on drop, which
/// covers a face the registry refused (a node already held) and a leg that ended before
/// connecting: neither may keep the open waiting. Paying is idempotent.
struct FaceOwed {
    /// The in-walk dial's signal: the walk waits for it before it releases the open.
    registered: Option<tokio::sync::oneshot::Sender<()>>,
    /// The start window a background or scouted endpoint is counted in.
    window: Option<Arc<StartWindow>>,
}

impl FaceOwed {
    fn none() -> Self {
        Self {
            registered: None,
            window: None,
        }
    }

    /// A debt the open's walk waits on, and the receiver it waits with.
    fn awaited_by_the_walk() -> (Self, tokio::sync::oneshot::Receiver<()>) {
        let (registered, paid) = tokio::sync::oneshot::channel();
        (
            Self {
                registered: Some(registered),
                window: None,
            },
            paid,
        )
    }

    fn pay(&mut self) {
        if let Some(registered) = self.registered.take() {
            let _ = registered.send(());
        }
        if let Some(window) = self.window.take() {
            window.one_connected();
        }
    }
}

impl Drop for FaceOwed {
    fn drop(&mut self) {
        self.pay();
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
    gate: Arc<ReadGate>,
}

impl FaceLeg {
    /// Drive this endpoint's face from `first` (already connected) or by
    /// connecting on `schedule` (a background endpoint), until the session
    /// closes. A background endpoint's first connect is what the start window
    /// waits on.
    ///
    /// `owed` is what the open is owed once this leg's FIRST face is registered; a background
    /// endpoint's is the start window, an in-walk dial's is the walk's own wait.
    async fn run(
        self,
        first: Option<OpenedSession>,
        schedule: Option<RetryPolicy>,
        mut owed: FaceOwed,
    ) {
        let mut session = first;
        let mut connecting = schedule;
        if session.is_none() {
            owed.window = Some(self.window.clone());
        }
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
            let mut closing = self.closing.clone();
            // `owed` is shared with the face, which may run on a thread of its own.
            let shared_owed = Arc::new(StdMutex::new(std::mem::replace(
                &mut owed,
                FaceOwed::none(),
            )));
            drive_face_on(
                self.face,
                opened,
                self.shared.clone(),
                async move {
                    let _ = closing.wait_for(|c| *c).await;
                },
                // After the registration, which is what the open is owed (see
                // [`FaceOwed`]); a face the registry refused never gets here, and is
                // paid below.
                {
                    let shared_owed = shared_owed.clone();
                    move || pay(&shared_owed)
                },
                self.gate.clone(),
            )
            .await;
            pay(&shared_owed);
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

/// A bound `listen` endpoint, and the parameters its accept loop mints the
/// sessions it accepts from: everything the `listen` role has decided before
/// it announces anything to the caller.
struct Listening {
    listener: BoundListener,
    params: SessionInitParams,
}

/// A bound listener together with what [`accept_faces`] needs beside it, as one
/// leg of a session that also dials. See [`drive_peer`].
struct ListenLeg {
    listening: Listening,
    offer: SessionOffer,
    clock: TokioTime,
    /// The endpoint's place in the `listen` list, which is what keeps the faces of two
    /// listeners apart (see [`accept_faces`]). The place it was STATED at, and not the order the
    /// binds finished in, so an endpoint bound late keeps its own range.
    index: u64,
}

/// Run `leg`'s accept loop as a local task, until `closing` is set. Called on a
/// `LocalSet`, because the accept loop's drive futures are not `Send`.
fn spawn_accept_leg(
    leg: ListenLeg,
    shared: &Arc<SharedSession>,
    gate: &Arc<ReadGate>,
    mut closing: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let ListenLeg {
        listening,
        offer,
        clock,
        index,
    } = leg;
    let shared = shared.clone();
    let gate = gate.clone();
    tokio::task::spawn_local(async move {
        accept_faces(listening, offer, clock, shared, index, &gate, async move {
            let _ = closing.wait_for(|c| *c).await;
        })
        .await;
    })
}

/// An endpoint of `listen` the bind phase left to the background: still to be bound, on its own
/// schedule, while the session is already open.
struct PendingBind {
    /// The endpoint's place in the `listen` list; see [`ListenLeg::index`].
    index: u64,
    endpoint: String,
    schedule: RetryPolicy,
}

/// What [`bind_listeners`] made of a `listen` list: the legs bound before the open went on, and
/// the endpoints still being bound after it.
struct BoundListeners {
    legs: Vec<ListenLeg>,
    /// R3089 -- bound by [`LateBinds::spawn`] once a role is running them.
    late: LateBinds,
}

/// R3089 -- the endpoints of `listen` that bind after the open has returned, with what binding
/// them needs: upstream's `spawn_add_listener`, run by the role that serves the faces.
///
/// A listener bound this way is served from the moment it binds, and told to a neighbour from
/// then on: the next Hello names it, and so does the next list gossip sends (MEASURED on the real
/// library: a Scout asked before the bind is answered with no locator and one asked after it with
/// the new one). A neighbour that already holds the list gossip sent before is not sent a new one.
struct LateBinds {
    pending: Vec<PendingBind>,
    tls: CapiTlsConfig,
    zid: Vec<u8>,
    link_tx: LinkTx,
    offer: SessionOffer,
    clock: TokioTime,
    /// Where each listener that binds late is told to the scouting responder; the responder reads
    /// the same handle ([`bound_responder`]).
    locators: LateLocators,
    /// The locators gossip tells for the listeners bound before the open returned, when the
    /// session gossips: a listener bound late adds its own to them.
    gossiped: Option<Vec<String>>,
}

impl LateBinds {
    /// Tell the scouting responder, and the gossip plane when the session has one, the locators of
    /// a listener that has just bound.
    fn advertise(
        locators: &LateLocators,
        gossiped: &Option<Vec<String>>,
        shared: &SharedSession,
        listener: &BoundListener,
    ) {
        let bound = Advertised::of(listener);
        locators.add(&bound.local, &bound.remote);
        if let Some(base) = gossiped {
            let mut all = base.clone();
            for locator in locators.snapshot().1 {
                if !all.contains(&locator) {
                    all.push(locator);
                }
            }
            shared.set_gossip_locators(all);
        }
    }

    /// The handle the responder of this session reads the locators of its late listeners from.
    fn locators(&self) -> LateLocators {
        self.locators.clone()
    }

    /// Gossip the locators of the listeners bound before the open returned, and those bound later
    /// after them.
    fn gossiping(mut self, bound_before: Vec<String>) -> Self {
        self.gossiped = Some(bound_before);
        self
    }

    /// Bind each pending endpoint, on its schedule, as a local task that serves its faces from the
    /// moment it binds, until `closing` is set. Called on a `LocalSet`, like [`spawn_accept_leg`].
    fn spawn(
        self,
        shared: &Arc<SharedSession>,
        gate: &Arc<ReadGate>,
        closing: &tokio::sync::watch::Receiver<bool>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let LateBinds {
            pending,
            tls,
            zid,
            link_tx,
            offer,
            clock,
            locators,
            gossiped,
        } = self;
        pending
            .into_iter()
            .map(|pending| {
                let (tls, zid) = (tls.clone(), zid.clone());
                let (shared, gate) = (shared.clone(), gate.clone());
                let (locators, gossiped) = (locators.clone(), gossiped.clone());
                let mut closing = closing.clone();
                tokio::task::spawn_local(async move {
                    let bound = retry_until_bound(pending.schedule, |_| {
                        bind_one(&pending.endpoint, &tls, &zid, link_tx)
                    });
                    let listening = tokio::select! {
                        listening = bound => listening,
                        _ = closing.wait_for(|c| *c) => return,
                    };
                    LateBinds::advertise(&locators, &gossiped, &shared, &listening.listener);
                    accept_faces(
                        listening,
                        offer,
                        clock,
                        shared,
                        pending.index,
                        &gate,
                        async move {
                            let _ = closing.wait_for(|c| *c).await;
                        },
                    )
                    .await;
                })
            })
            .collect()
    }

    /// Bind each pending endpoint and HOLD it for as long as this future is polled, serving no
    /// face: a client's listener is bound and serves nobody (see where the client role holds its
    /// own). Never completes.
    async fn hold(self) {
        let LateBinds {
            pending,
            tls,
            zid,
            link_tx,
            locators,
            ..
        } = self;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let held: Vec<_> = pending
                    .into_iter()
                    .map(|pending| {
                        let (tls, zid) = (tls.clone(), zid.clone());
                        let locators = locators.clone();
                        tokio::task::spawn_local(async move {
                            let listening = retry_until_bound(pending.schedule, |_| {
                                bind_one(&pending.endpoint, &tls, &zid, link_tx)
                            })
                            .await;
                            // A client that answers a Scout names its listener as it binds.
                            let bound = Advertised::of(&listening.listener);
                            locators.add(&bound.local, &bound.remote);
                            std::future::pending::<()>().await;
                        })
                    })
                    .collect();
                for task in held {
                    let _ = task.await;
                }
                // Nothing pending is nothing to hold, and the caller races this against the
                // role it holds for: it must not be the one that ends.
                std::future::pending::<()>().await;
            })
            .await;
    }
}

/// Say WHY an open failed, on stderr, when `WZ_CAPI_LOG` is set; return `()` so it drops into a
/// `map_err`.
///
/// The C caller is told only that the open failed (`Z_ERR_GENERIC`), and a program that prints
/// "Unable to open session!" has nothing more to say, so a failed bind, a refused dial and a
/// handshake that timed out read the same. zenoh-pico says which in its own debug log (a build
/// that logs prints `bind() failed for address 127.0.0.1: Address already in use`), and a flake
/// hunt on the drop-in legs found that without an equivalent here a failure on THIS side had no
/// evidence at all. Standard library only and silent unless asked: this crate has no logging
/// dependency, and an environment variable read once per failed open costs nothing on the path
/// that works.
fn log_open_failure(what: &str, why: &dyn core::fmt::Debug) {
    if std::env::var_os("WZ_CAPI_LOG").is_some() {
        std::eprintln!("[wz-capi] open failed: {what}: {why:?}");
    }
}

/// One attempt to bind `endpoint`, as the runtime's phase drivers ask for it: the listener, or
/// nothing.
async fn bind_one(
    endpoint: &str,
    tls: &CapiTlsConfig,
    zid: &[u8],
    link_tx: LinkTx,
) -> Result<Listening, ()> {
    bind_listener(endpoint, tls, zid, link_tx).await.ok_or(())
}

/// Bind the endpoints a session's `listen` states, in the order the config states them, under the
/// policy and the schedule of its bind phase.
///
/// R3076 -- upstream's `bind_listeners_impl` (`zenoh/src/net/runtime/orchestrator.rs` @
/// `async fn bind_listeners_impl(&self, listeners: &[EndPoint]) -> ZResult<()> {`) binds each in
/// turn, and an endpoint that cannot be bound ends the open when `listen/exit_on_failure` says so
/// (its default, `true`) and is skipped with a warning when it does not, even when none of them
/// can be bound. MEASURED on the real library with a second endpoint already taken: the default
/// opens with -4 though the first bound, and `exit_on_failure: false` opens with 0 whichever
/// endpoint is taken, the node then listening on the others and, with all taken, on nothing.
///
/// R3089 -- and the budget and the retry the real library gives a bind that fails, which
/// [`drive_bind_phase`] transcribes: with a `listen/timeout_ms` that is not zero, an endpoint that
/// cannot be bound is tried again on the `listen/retry` schedule, holding the open up until it
/// binds or the budget is spent (MEASURED: a port freed 700 ms in is bound at 1000 ms and the
/// open returns then; a port that stays taken fails the open with -4 at the budget), or, when
/// `exit_on_failure` is false, tried in the background while the open returns at once (MEASURED:
/// 2 ms, and the port answers a connect once it is freed).
///
/// `None` is an open failure, which the caller reports. The legs come back in the order that
/// they were bound; each carries the place its endpoint was stated at, and that is what names its
/// face ids.
async fn bind_listeners(
    endpoints: &[String],
    phase: ListenPhase,
    tls: &CapiTlsConfig,
    zid: &[u8],
    link_tx: LinkTx,
    offer: SessionOffer,
    clock: TokioTime,
) -> Option<BoundListeners> {
    let outcome = drive_bind_phase(phase.policy, phase.schedule, endpoints, |position, _| {
        bind_one(&endpoints[position], tls, zid, link_tx)
    })
    .await
    .map_err(|e| log_open_failure("bind phase", &e))
    .ok()?;
    let legs = outcome
        .bound
        .into_iter()
        .map(|(position, listening)| ListenLeg {
            listening,
            offer,
            clock,
            index: position as u64,
        })
        .collect();
    let pending = outcome
        .background
        .into_iter()
        .map(|(position, schedule)| PendingBind {
            index: position as u64,
            endpoint: endpoints[position].clone(),
            schedule,
        })
        .collect();
    Some(BoundListeners {
        legs,
        late: LateBinds {
            pending,
            tls: tls.clone(),
            zid: zid.to_vec(),
            link_tx,
            offer,
            clock,
            locators: LateLocators::default(),
            gossiped: None,
        },
    })
}

/// Bind the session's `listen` endpoint. `None` is an open failure, which the
/// caller reports.
///
/// R3067 -- split out of the listen role so a session that also dials binds
/// its listener the same way, and first, as upstream does
/// (`zenoh/src/net/runtime/orchestrator.rs` @
/// `self.bind_listeners(&listeners).await?;` before `self.connect_peers`).
async fn bind_listener(
    endpoint: &str,
    tls: &CapiTlsConfig,
    zid: &[u8],
    link_tx: LinkTx,
) -> Option<Listening> {
    // Everything that can fail the open runs BEFORE the success signal the
    // caller sends, so a failure is reported to the C caller rather than
    // silently killing a listener it was told had opened.
    // R311y406 / R311y534 — thread the LISTEN server cert (native
    // Z_CONFIG_TLS_LISTEN_* keys, path or inline base64) into the bind's
    // AcceptConfig, so a `z_open(listen="tls/..")` or `z_open(listen="quic/..")`
    // carrying the cert presents it (was a cert-free `bind_endpoint` ->
    // cert-absence reject). Each backend's slot is filled only when its feature
    // is compiled in; without it that scheme surfaces `Unsupported` at bind
    // regardless -- see `listen_accept_config`.
    let accept_cfg = listen_accept_config(tls)
        .map_err(|e| log_open_failure("listen configuration", &e))
        .ok()?;
    let listener = bind_endpoint_with_config(endpoint, &accept_cfg)
        .await
        .map_err(|e| log_open_failure(&format!("bind {endpoint}"), &e))
        .ok()?;
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
    // R311y820 — drawn HERE, above the `tx.send(true)` the caller sends, and the
    // placement is the point: after that send the C caller has already been told
    // the open succeeded, so an entropy failure could only be reported as "no
    // peer ever connects". Built before the bind is announced, it is an ordinary
    // open failure like the two above.
    let params = init_params(WhatAmI::Peer, zid.to_vec(), link_tx)
        .map_err(|e| log_open_failure(&format!("session parameters for {endpoint}"), &e))
        .ok()?;
    Some(Listening { listener, params })
}

/// The [`FaceExecutor`] of a [`FaceDrive::PerFace`] node: every face's drive runs on a thread of
/// its own ([`run_on_own_thread`]), polled only while the node's read task may run, as the
/// top-level drive is ([`Pausable`]), and is one of the futures a stop waits for.
struct GateFaces {
    gate: Arc<ReadGate>,
}

impl FaceExecutor for GateFaces {
    fn wrap(&self, drive: SpawnedDrive) -> SpawnedDrive {
        run_on_own_thread(self.gate.clone(), drive)
    }
}

/// Accept on a bound listener until `shutdown`, driving every accepted peer as the session's
/// [`FaceDrive`] says.
///
/// The accept loop is the CONTROL plane and runs on this one task: it accepts, runs each
/// handshake, bounds the sessions and lands each face in the registry through
/// `CApiForwarder`. Under [`FaceDrive::Serial`] it drives the faces too, one after another on
/// this task, which is zenoh-pico's contract. Under [`FaceDrive::PerFace`] the DATA plane is
/// not here: the drive of each face runs on a thread of its own ([`GateFaces`]), so N peers
/// are read, decoded and delivered by N threads, and a callback that blocks holds up its own
/// peer alone. Shutdown is a future the loop races, so a `z_close` with NO peer ever connected
/// unwinds a pending `accept()` cleanly.
///
/// R3076 -- `index` is the listener's place among the session's, and the faces it accepts are
/// numbered inside its own range of the registry's face ids ([`CApiForwarder::listening`]): each
/// accept loop counts its faces from zero, so two listeners that shared the registry unshifted
/// would each hand it a face 0.
async fn accept_faces(
    listening: Listening,
    offer: SessionOffer,
    clock: TokioTime,
    shared: Arc<SharedSession>,
    index: u64,
    gate: &Arc<ReadGate>,
    shutdown: impl Future<Output = ()>,
) {
    // pico accepts in a task of its executor, so a listener opened without the
    // read task is BOUND and accepts nobody until it is started: a peer that
    // dials meanwhile waits in the backlog, and is served once the task starts.
    gate.wait_running().await;
    let forwarder = Arc::new(CApiForwarder::listening(shared, index));
    let Listening { listener, params } = listening;
    match gate.face_drive() {
        FaceDrive::Serial => {
            let _summary = accept_loop_offering(
                listener,
                params,
                offer,
                clock,
                DEFAULT_OPEN_TICK_MS,
                shutdown,
                |_event| {},
                &*forwarder,
            )
            .await;
        }
        FaceDrive::PerFace => {
            let _summary = accept_loop_offering_spawned(
                listener,
                params,
                offer,
                clock,
                DEFAULT_OPEN_TICK_MS,
                shutdown,
                |_event| {},
                forwarder,
                Arc::new(GateFaces { gate: gate.clone() }),
            )
            .await;
        }
    }
}

/// The `listen` role: bind, unblock `z_open` immediately, then hold N
/// concurrent inbound peers until `z_close` — pico's non-blocking listener.
///
/// R3076 -- over every endpoint the session states, each with its own accept loop on a
/// `LocalSet` (the loops' drive futures are not `Send`), as [`drive_peer`] runs its own.
async fn drive_listen(
    endpoints: Vec<String>,
    tls: CapiTlsConfig,
    whatami: WhatAmI,
    ctx: DriveContext,
) {
    let DriveContext {
        zid,
        shared,
        tx,
        shutdown,
        stop,
        clock,
        link_tx,
        offer,
        gate,
        // A listener that is not also a dialler scouts for nobody (see `open_blocking`'s
        // routing), and is still FOUND when its plan answers.
        scouting,
        // And gossips to nobody: a listener that gossips is routed to the dial role, which is
        // the one that dials what it is told of.
        dials: _,
        gossiping: _,
        listen_phase,
    } = ctx;
    let Some(BoundListeners { legs, late }) =
        bind_listeners(&endpoints, listen_phase, &tls, &zid, link_tx, offer, clock).await
    else {
        let _ = tx.send(false);
        return;
    };
    let listeners: Vec<&BoundListener> = legs.iter().map(|leg| &leg.listening.listener).collect();
    let _findable = match bound_responder(
        scouting.as_ref(),
        whatami,
        &zid,
        &listeners,
        late.locators(),
    )
    .await
    {
        Ok(responder) => responder.map(Responder::start),
        Err(()) => {
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
    if gate.announce_open(&tx) {
        return;
    }
    let (closing_tx, closing_rx) = tokio::sync::watch::channel(false);
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut accepts: Vec<_> = legs
                .into_iter()
                .map(|leg| spawn_accept_leg(leg, &shared, &gate, closing_rx.clone()))
                .collect();
            // R3089 -- and the listeners whose bind goes on in the background.
            accepts.extend(late.spawn(&shared, &gate, &closing_rx));
            // R311y557 — the LISTEN role is where the local plane matters most: a
            // listener is unblocked by the BIND, so every put it makes before its first
            // peer connects had nowhere to deliver in-process. The drain rides this
            // task's `select!` for the same one-task reason `drive_dial` does.
            tokio::select! {
                _ = shared.drive_local_plane() => {}
                _ = shutdown_future(shutdown, stop) => {}
            }
            let _ = closing_tx.send(true);
            for accept in accepts {
                let _ = accept.await;
            }
        })
        .await;
}

/// A session with no endpoint at all: the open is the whole of it, and what the
/// session does is deliver to itself.
///
/// R3067 -- zenoh starts a peer or router that has nothing to listen on,
/// nothing to connect to and no scouting without complaint: it is alone, and
/// its own publishers and subscribers still meet (measured on the real library,
/// `open` answers 0 and a same-session subscriber is delivered). Before this a
/// config like that was refused, which no program written for zenoh-c expects.
async fn drive_idle(whatami: WhatAmI, ctx: DriveContext) {
    let DriveContext {
        zid,
        shared,
        tx,
        shutdown,
        stop,
        gate,
        scouting,
        ..
    } = ctx;
    // R3071 -- a session with no listener is still findable when it answers a Scout: it says
    // what it is and that it has nowhere to be dialled, as upstream's does for `listen: []`.
    let _findable = match bound_responder(
        scouting.as_ref(),
        whatami,
        &zid,
        &[],
        LateLocators::default(),
    )
    .await
    {
        Ok(responder) => responder.map(Responder::start),
        Err(()) => {
            let _ = tx.send(false);
            return;
        }
    };
    if gate.announce_open(&tx) {
        return;
    }
    tokio::select! {
        _ = shared.drive_local_plane() => {}
        _ = shutdown_future(shutdown, stop) => {}
    }
}

/// What the calling ABI, and the config it read, decide about the session being
/// opened — as distinct from where it connects.
///
/// Grouped rather than passed one by one, on the rule `DriveContext` states:
/// these three travel together by construction, each is a fact the two ABIs
/// answer differently, and a fourth parameter beside them was the one that took
/// [`open_blocking`] past clippy's limit. The alternative, an `#[allow]` on the
/// function, would be an escape hatch disabling the lint at the site it fired on.
pub struct OpenStance {
    /// The transmit model of the ABI calling this. The two ABIs this core serves
    /// transmit differently: a zenoh-c session puts onto zenoh's bounded queue
    /// and drops a droppable message after `wait_before_drop`
    /// ([`TxQueueConf::default`]), while pico writes on the caller's thread and
    /// never drops for a full socket ([`TxQueueConf::pico`]).
    pub tx_queue: TxQueueConf,
    /// The batch size the session advertises at its handshake, dialled and accepted alike; see
    /// [`LinkTx`]. A zenoh-c session reads it from `transport/link/tx/batch_size` and a session
    /// whose config states none passes [`DEFAULT_BATCH_SIZE`]; zenoh-pico's ABI has no such key
    /// and passes the constant.
    pub batch_size: u16,
    /// What the session's links offer at their handshake, every dialled link and
    /// every accepted one alike: the other half of the same fact. A zenoh-c
    /// session offers what its config enables — QoS, and shared memory on the
    /// shared-memory build, are on by default upstream — while zenoh-pico
    /// negotiates none of them on unicast (its InitSyn carries the patch ext and
    /// nothing else, `vendor/zenoh-pico/src/protocol/codec/transport.c` @
    /// `z_result_t _z_init_encode(`) and passes [`SessionOffer::universal`]. It
    /// is a value the caller supplies rather than one this crate derives because
    /// the two ABIs read their configs through different keys.
    pub offer: SessionOffer,
    /// The id the config STATES, or `None` for a session that states none. Given
    /// for the same reason as `offer`: zenoh-c reads its `id` key and zenoh-pico
    /// its numeric one, each with its own refusals, and what reaches here is
    /// already a [`ConfiguredZid`], so this crate restates neither.
    pub zid: Option<ConfiguredZid>,
    /// Whether the session's read task runs from the start. zenoh-pico starts its
    /// executor in `z_open` only if the caller's `auto_start_read_task` is set
    /// (default true), and a zenoh-c session has no such switch, so it always
    /// passes true. False opens a session that connects or binds and then reads
    /// nothing until [`SessionState::start_read_task`]; see [`ReadGate`].
    pub start_read_task: bool,
    /// R3064 -- the node's `timestamping.enabled` map: which roles hold a clock. Read from the
    /// config by the ABI that reads configs (`ZenohConfigIngest::timestamping_enabled` in the
    /// runtime, for zenoh-c), and [`TimestampingEnabled::default`] (zenoh's shipped map: only a router
    /// stamps) for an ABI that has no such key, which is what every session was given before
    /// this field existed. The session builds ONE clock from it, for the role it dials as, and
    /// every session of the node shares that clock.
    pub timestamping: TimestampingEnabled,
    /// R3065 -- the shared-memory reader this session was opened over: the clients its node's
    /// storage resolved into, or `None` for the default reader (POSIX alone). It reaches the
    /// registry, which gives it to the plane and to every face session. The list its auth segment
    /// advertises is [`Self::offer`]'s, and the two are set together by [`Self::with_shm_clients`]
    /// so that a node never lists a protocol its reader cannot resolve.
    pub shm_clients: OpenShmClients,
    /// R3069 -- who runs the callbacks of a delivery the session makes to ITSELF; see
    /// [`SessionResources::local_delivery`]. zenoh-pico's ABI says [`LocalDeliveryDrain::DriveTask`]
    /// and zenoh-c's says [`LocalDeliveryDrain::Caller`].
    pub local_delivery: LocalDeliveryDrain,
    /// R3070 -- what the session does with multicast scouting, or `None` for a session that does
    /// not scout: zenoh-pico's ABI, whose scouting is a call a program makes, and a config that
    /// turned it off. A peer or router that has a plan dials what it finds beside its endpoints;
    /// a client with no endpoint scouts for the first node it can open to. A plan whose matcher
    /// is empty (a router's default) looks for nobody and is the same as `None`.
    pub scouting: Option<ScoutingPlan>,
    /// R3073 -- whether a face this node reaches as a north-bound peer is ended with the
    /// `DeclareFinal` of the initial interest; see [`SessionResources::initial_interest`].
    /// Both ABIs say `true`: zenoh-c's peer hat sends it to a peer it meets as a north-bound
    /// peer, and zenoh-pico's session sends it to every peer link it adds as a peer. The rule
    /// itself only sends from a peer to a peer, so a client session sends none either way.
    pub initial_interest: bool,
    /// R3074 -- how a peer or router session gossips, or `None` for one that does not: it tells
    /// a face it meets which nodes it knows and where they are, and dials the nodes it is told
    /// of ([`SessionResources::gossip`]). zenoh-c's ABI resolves it from its config (R3075: the
    /// four `scouting/gossip` keys a C session reads), which is zenoh's shipped policy when the
    /// config says nothing and `None` when it turns gossip off; zenoh-pico's says `None`, its
    /// peers being introduced by scouting alone. A client never gossips whatever this says.
    pub gossip: Option<GossipPolicy>,
    /// R3076 -- what an endpoint of `listen` that cannot be bound does to the open, which is
    /// upstream's `listen/exit_on_failure` and its default (`true`): with `false` that endpoint
    /// is skipped and the session listens on the others, or on nothing. R3089 -- and with
    /// `listen/timeout_ms` and `listen/retry` how long and how often it is tried first. zenoh-c's
    /// ABI reads them from its config; zenoh-pico's says [`ListenPhase::SHIPPED`], its listener
    /// being one endpoint whose failure has always failed the open at the first attempt.
    pub listen_phase: ListenPhase,
    /// Where the faces of the session are driven: zenoh-pico's ABI says [`FaceDrive::Serial`],
    /// its callbacks all running on its one read task, and zenoh-c's says
    /// [`FaceDrive::PerFace`], its callbacks being concurrent across links.
    pub face_drive: FaceDrive,
}

#[cfg(feature = "session-extshm")]
impl OpenStance {
    /// This stance for a session opened over the client `set`: the reader is the set, and the
    /// protocols the offer advertises are exactly the set's. `Err` when the set names more
    /// protocols than an auth segment has slots for.
    pub fn with_shm_clients(
        mut self,
        set: Arc<wz_runtime_tokio::shm_clients::ShmClientSet>,
    ) -> Result<Self, wz_runtime_tokio::shm_clients::TooManyShmProtocols> {
        self.offer = self.offer.with_shm_protocols(set.advertised()?);
        self.shm_clients = Some(set);
        Ok(self)
    }
}

/// The stack, in bytes, of the thread a session's drive runs on.
///
/// The thread's stack is the one thing about it the host chooses and not the platform: a thread
/// spawned with no size gets 2 MiB (Linux and macOS) or 1 MiB (Windows), and everything the
/// session does on it, accepting a face, running its handshake, taking in what it sends and
/// answering it, is polled on that stack. An unoptimised build gives those futures frames of
/// tens of KiB each, and a topology list a node is told of (gossip, R3074) is built and read
/// through bounded containers the codec holds inline, which is a frame of its own on top of
/// them. MEASURED on Linux, debug, with the three C ABI crates built together (so that one
/// feature set serves them all): with every listening peer gossiping, 2 MiB aborts with
/// `thread 'wz-capi-drive' has overflowed its stack` in eight test binaries and 3 MiB passes,
/// where the same tests pass at 2 MiB with the node told not to gossip. Windows' debug codegen spends more per frame
/// than Linux's, which is why the demo, which polls the same futures on a thread of its own,
/// states 16 MiB for every host (`DEMO_STACK_BYTES`), and so does this: the budget is the
/// session's, the same on every host, and the pages are reserved and not touched until used.
const DRIVE_THREAD_STACK_BYTES: usize = 16 * 1024 * 1024;

/// How many worker threads a session's runtime has. They run the socket reactor, the writers and
/// the control tasks (a dial and its waiting); a face's own drive, and so its callbacks, runs on
/// a thread of its own under [`FaceDrive::PerFace`] and not here, so this is not the node's
/// receive parallelism.
///
/// Two by default, which is what the reactor and the writers of a node of a few links need; a
/// runtime is made PER session and a program may open many. `WZ_CAPI_WORKER_THREADS` raises it
/// for a node whose writers are the limit.
fn drive_workers() -> usize {
    std::env::var("WZ_CAPI_WORKER_THREADS")
        .ok()
        .and_then(|text| text.parse::<usize>().ok())
        .filter(|workers| *workers >= 1)
        .unwrap_or(2)
}

/// Open a session: spawn the drive thread and wait for the role's open
/// outcome. For `connect` that is the settled handshake; for `listen` it is
/// only the bind.
///
/// R3067 -- the roles are a SET: `connect` and `listen` together are a peer
/// that dials and accepts (its listener bound first, then its dials, the open
/// outcome that of the dials), and neither is a session that delivers only to
/// itself. A client stated with both binds its listener and serves nothing on
/// it, which is what the real library opens it as.
///
/// `dial_phase` decides how long the `connect` role keeps trying before it
/// reports the failure; the `listen` role does not read it. `stance` is what the
/// calling ABI decides about the session itself: see [`OpenStance`].
pub fn open_blocking(
    connect: Vec<String>,
    listen: Vec<String>,
    tls: CapiTlsConfig,
    dial_whatami: WhatAmI,
    dial_phase: DialPhase,
    stance: OpenStance,
) -> Result<SessionState, OpenError> {
    let OpenStance {
        tx_queue,
        batch_size,
        offer,
        zid,
        start_read_task,
        timestamping,
        shm_clients,
        local_delivery,
        scouting,
        initial_interest,
        gossip,
        listen_phase,
        face_drive,
    } = stance;
    let link_tx = LinkTx {
        queue: tx_queue,
        batch_size,
    };
    let clock = TokioTime::new();
    // R3074 -- where the nodes a peer is told of are posted. Made here because both ends are
    // needed before the drive thread starts: the registry's plane holds the sender, and the
    // role that dials holds the receiver.
    let (dial_tx, dial_rx) = tokio::sync::mpsc::unbounded_channel();
    let gossip = gossip.filter(|_| dial_whatami != WhatAmI::Client);
    let gossiping = gossip.is_some();
    // Fixed here, on the CALLING thread, so `SessionState` can hand it to
    // `z_info_zid` and the INIT cannot disagree with it — see the field doc.
    let (zid, wire_zid) = session_zids(zid).ok_or(OpenError::DriveFailed)?;
    // R3064 -- the node's clock, built ONCE here from the identity just fixed and the role the
    // session plays, and handed to the registry, which installs a clone on its plane and on every
    // face session it makes. `None` inside when the config does not enable timestamping for this
    // role, which is zenoh's own answer (`enabled().get(whatami)`) and the shipped one for a peer
    // or client.
    let node_hlc = NodeHlc::for_node(&wire_zid, dial_whatami, timestamping);
    // R311y820 — one line below the mint, and fallible for the same reason:
    // both need OS entropy and neither has an honest constant to fall back to.
    let shared = Arc::new(
        SharedSession::new_with_resources(
            clock,
            wire_zid.clone(),
            SessionResources {
                node_hlc,
                shm_clients,
                local_delivery,
                initial_interest,
                gossip: gossip.map(|policy| GossipSetup {
                    whatami: dial_whatami,
                    policy,
                    dials: dial_tx.clone(),
                }),
            },
        )
        .map_err(|_| OpenError::DriveFailed)?,
    );
    let shutdown = Arc::new(Notify::new());
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<bool>();

    let drive_shared = shared.clone();
    let drive_shutdown = shutdown.clone();
    let drive_stop = stop.clone();
    let read_gate = Arc::new(ReadGate::new(start_read_task).with_face_drive(face_drive));
    let drive_gate = read_gate.clone();

    // One dedicated multi-thread runtime PER session, owned by its driver
    // thread: the `block_on` future need not be `Send` (the control plane, the
    // accept loops and the local plane, stay on it), while the socket writer
    // tasks and the I/O reactor run on the runtime's worker threads. The DRIVE OF
    // EACH FACE runs on the drive thread under `FaceDrive::Serial` and on a thread
    // of its own under `FaceDrive::PerFace` ([`run_on_own_thread`]), never on a
    // worker: a pool cannot keep a blocked callback from holding the face beside
    // it. A shared runtime driven by two `block_on`s starved the concurrent
    // handshake (the acceptor timed out into a pre-Established Terminal);
    // per-session isolation lets each session drive its own links.
    //
    // The workers carry the stack of the drive thread, because the control tasks they
    // run (a dial's handshake) poll the same futures (see [`DRIVE_THREAD_STACK_BYTES`]).
    let handle = std::thread::Builder::new()
        .name("wz-capi-drive".to_owned())
        .stack_size(DRIVE_THREAD_STACK_BYTES)
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(drive_workers())
                .thread_stack_size(DRIVE_THREAD_STACK_BYTES)
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
                zid: wire_zid,
                shared: drive_shared,
                tx,
                shutdown: drive_shutdown,
                stop: drive_stop,
                clock,
                link_tx,
                offer,
                gate: drive_gate.clone(),
                scouting,
                dials: (dial_tx, dial_rx),
                gossiping,
                listen_phase,
            };
            // R3070 -- a session that scouts for nodes to connect to dials them with the dial
            // role, whether or not it was also told an endpoint, so the plan decides the route
            // alongside the endpoints: a router's empty one scouts for nobody and routes as before.
            let scouts = ctx.scouting.as_ref().is_some_and(ScoutingPlan::scouts);
            // R3074 -- and a listener that gossips is a peer that dials what it is told of, so
            // it takes the dial role as one that scouts does. A session that gossips with no
            // listener and nothing to connect to has nobody to be told of by, and stays alone.
            let gossips_with_a_listener = ctx.gossiping && !listen.is_empty();
            // Polled only while the read task may run ([`Pausable`]): a stopped
            // task is a session nobody is driving, which is what pico's is.
            rt.block_on(Pausable::new(drive_gate, async move {
                if !connect.is_empty() || scouts || gossips_with_a_listener {
                    drive_dial(connect, listen, dial_whatami, tls, dial_phase, ctx).await;
                } else if !listen.is_empty() {
                    drive_listen(listen, tls, dial_whatami, ctx).await;
                } else {
                    // R3067 -- no endpoint: a session alone, as zenoh starts one.
                    // Whether a config MAY open without one is the calling ABI's
                    // decision (a client may not, and a peer that scouts reaches
                    // others through it), so it is asked there, not here.
                    drive_idle(dial_whatami, ctx).await;
                }
            }));
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
            abi_extension: std::sync::OnceLock::new(),
            read_gate,
        }),
        _ => {
            // Open failed (bind / link / handshake error, or the drive thread
            // returned without opening). Join the finished thread and report.
            let _ = handle.join();
            Err(OpenError::DriveFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configured id is read the way zenoh reads it, in both forms it takes.
    ///
    /// The expected bytes come from the documented reading and from nothing in
    /// this crate: the text is a `u128` in big-endian hex, the id's little-endian
    /// bytes are what `z_id_t` holds, and the INIT carries them with the trailing
    /// zeros trimmed. A parser that read the text per byte in written order
    /// would give `c1 1e 47 c1 1e 49` for the first case and fail here.
    ///
    /// The refused list is the one `libzenohc.so` 1.10.0 refused when the same
    /// text was inserted as the config's `id`, and the accepted list includes the
    /// two that look wrong and are taken (an odd number of digits, a leading `+`).
    #[test]
    fn a_configured_id_is_read_as_zenoh_reads_it() {
        let expected = |text: &str| -> ([u8; ZID_LENGTH], Vec<u8>) {
            let bytes = u128::from_str_radix(text, 16).expect("hex").to_le_bytes();
            let mut trimmed = bytes.to_vec();
            while trimmed.last() == Some(&0) {
                trimmed.pop();
            }
            (bytes, trimmed)
        };
        for text in [
            "1",
            "c11e47c11e49",
            "abc",
            "ffffffffffffffffffffffffffffffff",
            "+1",
        ] {
            let configured = ConfiguredZid::from_zenoh_text(text)
                .unwrap_or_else(|| panic!("zenoh accepts `{text}`"));
            let (padded, wire) = expected(text);
            assert_eq!(configured.padded(), padded, "state form of `{text}`");
            assert_eq!(configured.wire(), wire.as_slice(), "wire form of `{text}`");
        }
        // The two forms of the id the probe configures.
        let six = ConfiguredZid::from_zenoh_text("c11e47c11e49").expect("accepted");
        assert_eq!(six.wire(), &[0x49, 0x1e, 0xc1, 0x47, 0x1e, 0xc1]);
        assert_eq!(
            &six.padded()[6..],
            &[0u8; 10],
            "zero padding is part of the state form"
        );

        for text in [
            "",
            "0",
            "01",
            "0a0b",
            "ABC",
            "zz",
            "1ffffffffffffffffffffffffffffffff",
        ] {
            assert!(
                ConfiguredZid::from_zenoh_text(text).is_none(),
                "zenoh refuses `{text}`, so no configured id can be built from it"
            );
        }
    }

    /// The form that goes on the wire is the TRIMMED one, and the form
    /// `z_info_zid` reports is the padded one, both from one choice.
    ///
    /// Nothing else holds this: the differential against the real library reads
    /// `z_info_zid`, which is padded whichever form the INIT carries, so a session
    /// that put sixteen bytes with ten zeros on the wire would pass it. This is
    /// the choice itself, asked with no peer.
    #[test]
    fn a_configured_id_goes_on_the_wire_trimmed_and_reads_back_padded() {
        let configured = ConfiguredZid::from_zenoh_text("c11e47c11e49").expect("accepted");
        let (state, wire) = session_zids(Some(configured)).expect("no entropy needed");
        assert_eq!(
            wire,
            vec![0x49, 0x1e, 0xc1, 0x47, 0x1e, 0xc1],
            "the INIT's bytes"
        );
        assert_eq!(&state[..6], wire.as_slice(), "the same id");
        assert_eq!(&state[6..], &[0u8; 10], "padded for z_info_zid");

        // No id: the trimmed form of the minted sixteen bytes on the wire, and a new one each
        // time.
        let (state_a, wire_a) = session_zids(None).expect("entropy");
        let (state_b, _) = session_zids(None).expect("entropy");
        assert_eq!(
            wire_a.as_slice(),
            wz_runtime_tokio::zid_hex::canonical_zid(&state_a),
            "one choice, two views"
        );
        assert_ne!(state_a, state_b, "a session with no id mints its own");
    }

    /// A minted id whose last byte is zero (one in 256) is fifteen bytes on the wire and
    /// sixteen to `z_info_zid`, as a configured one is.
    ///
    /// It went out as sixteen. The routing graph holds an id trimmed, so a node a gossip
    /// list named was not the node the link then opened to, the dial was closed, and the
    /// chain of five peers of the gossip differential ended one link short in about one run in
    /// fifty (its first node dials three others, in each of two arms).
    #[test]
    fn a_minted_id_with_a_zero_tail_goes_on_the_wire_trimmed() {
        let mut minted = [0x11u8; ZID_LENGTH];
        minted[ZID_LENGTH - 1] = 0;
        let (state, wire) = minted_zids(minted);
        assert_eq!(state, minted, "z_info_zid reports all sixteen");
        assert_eq!(
            wire.as_slice(),
            &minted[..ZID_LENGTH - 1],
            "the INIT's bytes"
        );

        let mut longer = [0x22u8; ZID_LENGTH];
        longer[ZID_LENGTH - 3..].fill(0);
        let (_, wire) = minted_zids(longer);
        assert_eq!(wire.len(), ZID_LENGTH - 3, "every trailing zero byte goes");
    }

    /// The node a link opened to is the node that was dialled whatever the spelling of its id:
    /// the expected one is read off the routing graph (trimmed), the other off the handshake.
    #[test]
    fn a_link_to_the_dialled_node_is_the_dialled_node_whatever_its_zero_tail() {
        let trimmed = [0x0a, 0x0b, 0x0c];
        let padded = [0x0a, 0x0b, 0x0c, 0x00];
        assert!(is_expected_peer(Some(&padded), &trimmed));
        assert!(is_expected_peer(Some(&trimmed), &padded));
        assert!(is_expected_peer(Some(&trimmed), &trimmed));
        assert!(!is_expected_peer(None, &trimmed), "no peer id is no match");
        assert!(
            !is_expected_peer(Some(&[0x0a, 0x0b, 0x0d, 0x00]), &trimmed),
            "another node whose id has a zero tail is another node"
        );
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a current-thread runtime")
    }

    /// `delay`, then `act`, on a thread of its own: the C thread that starts or
    /// closes a session the drive thread has stopped polling.
    fn later(delay_ms: u64, act: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            act();
        })
    }

    /// The state pico's `zp_read_task_is_running` reads, through every transition:
    /// start and stop are idempotent, and a closed session runs nothing.
    #[test]
    fn the_read_task_flag_follows_start_stop_and_close() {
        let gate = ReadGate::new(true);
        assert!(gate.is_running(), "auto_start_read_task true starts it");
        gate.stop().expect("a stop off the drive thread");
        gate.stop().expect("a stop off the drive thread");
        assert!(!gate.is_running(), "a stop is idempotent");
        gate.start().expect("a start off the drive thread");
        gate.start().expect("a start off the drive thread");
        assert!(gate.is_running(), "a start is idempotent");
        assert!(!ReadGate::new(false).is_running(), "false opens it stopped");
        gate.close();
        assert!(!gate.is_running(), "a closed session runs nothing");
    }

    /// The open is never gated: a gate that starts stopped still lets the role
    /// connect or bind, because pico does both inside `z_open`, before any
    /// executor could run. It holds the drive only from the announcement.
    #[test]
    fn a_gate_that_starts_stopped_lets_the_open_through() {
        let gate = Arc::new(ReadGate::new(false));
        let ran = Arc::new(AtomicBool::new(false));
        let ran_in = ran.clone();
        runtime().block_on(Pausable::new(gate.clone(), async move {
            ran_in.store(true, Ordering::SeqCst)
        }));
        assert!(
            ran.load(Ordering::SeqCst),
            "the open was held by a stopped gate"
        );

        let (tx, rx) = mpsc::channel::<bool>();
        assert!(!gate.announce_open(&tx), "the receiver is alive");
        assert_eq!(rx.recv(), Ok(true));
        assert!(
            !gate.drive_may_run(),
            "after the announcement a stopped gate holds the drive"
        );
    }

    /// A stopped read task is not polled AT ALL, and a start resumes it. The
    /// future reads the gate on its first poll, so a poll made while stopped
    /// would record `false`: nothing about timing is asserted.
    #[test]
    fn a_stopped_read_task_is_not_polled_until_it_is_started() {
        let gate = Arc::new(ReadGate::new(true));
        gate.mark_opened();
        gate.stop().expect("a stop off the drive thread");
        let running_when_polled = Arc::new(AtomicBool::new(false));
        let seen = running_when_polled.clone();
        let inner_gate = gate.clone();
        let starter = later(150, {
            let gate = gate.clone();
            move || gate.start().expect("a start off the drive thread")
        });
        runtime().block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                Pausable::new(gate.clone(), async move {
                    seen.store(inner_gate.is_running(), Ordering::SeqCst);
                }),
            )
            .await
            .expect("a start must resume a stopped read task");
        });
        starter.join().expect("the starter");
        assert!(
            running_when_polled.load(Ordering::SeqCst),
            "the drive was polled while the read task was stopped"
        );
    }

    /// Closing passes a stopped gate. Without it `SessionState::close` would join a
    /// thread that is waiting for the close: the stop latch and the notify reach
    /// only a future that is polled.
    #[test]
    fn a_close_wakes_a_stopped_read_task() {
        let gate = Arc::new(ReadGate::new(true));
        gate.mark_opened();
        gate.stop().expect("a stop off the drive thread");
        let closer = later(150, {
            let gate = gate.clone();
            move || gate.close()
        });
        runtime().block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                Pausable::new(gate.clone(), async {}),
            )
            .await
            .expect("a close must wake a stopped read task");
        });
        closer.join().expect("the closer");
    }

    /// The face-level wait: held while stopped, released by a start and by a
    /// close.
    #[test]
    fn a_face_waits_for_the_read_task_and_a_close_releases_it() {
        let gate = Arc::new(ReadGate::new(false));
        let rt = runtime();
        let held = rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(100), gate.wait_running()).await
        });
        assert!(held.is_err(), "a stopped read task must hold the face");

        let starter = later(100, {
            let gate = gate.clone();
            move || gate.start().expect("a start off the drive thread")
        });
        rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10), gate.wait_running()).await
        })
        .expect("a start must release the face");
        starter.join().expect("the starter");

        gate.stop().expect("a stop off the drive thread");
        let closer = later(100, {
            let gate = gate.clone();
            move || gate.close()
        });
        rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10), gate.wait_running()).await
        })
        .expect("a close must release the face");
        closer.join().expect("the closer");
    }

    /// Stop the gate from a thread of its own and fail if that does not return in
    /// five seconds: a stop that never returns is the defect, and it must read as
    /// a failed test rather than a hung one.
    fn stop_within_five_seconds(gate: &Arc<ReadGate>) {
        let (tx, rx) = mpsc::channel();
        let stopper = gate.clone();
        std::thread::spawn(move || {
            stopper.stop().expect("a stop off the drive thread");
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("a stop did not return within five seconds");
    }

    /// Spin until `cond` holds, or fail after ten seconds.
    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !cond() {
            assert!(std::time::Instant::now() < deadline, "never saw: {what}");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// A stop is synchronous. The drive thread runs a future whose every step
    /// blocks for a while, as a callback does; the stop is made while one is
    /// running and must return only when it is over, after which nothing runs
    /// until a start. A stop that returned at once would leave `in_flight` set.
    #[test]
    fn a_stop_returns_only_when_no_callback_is_running() {
        let gate = Arc::new(ReadGate::new(true));
        gate.mark_opened();
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let drive = {
            let (gate, polls, in_flight, done) =
                (gate.clone(), polls.clone(), in_flight.clone(), done.clone());
            std::thread::spawn(move || {
                runtime().block_on(Pausable::new(gate, async move {
                    while !done.load(Ordering::SeqCst) {
                        in_flight.store(true, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(40));
                        polls.fetch_add(1, Ordering::SeqCst);
                        in_flight.store(false, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                    }
                }));
            })
        };

        wait_until("a step in flight", || in_flight.load(Ordering::SeqCst));
        stop_within_five_seconds(&gate);
        assert!(
            !in_flight.load(Ordering::SeqCst),
            "the stop returned while a step was still running"
        );
        let frozen = polls.load(Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(
            polls.load(Ordering::SeqCst),
            frozen,
            "the drive ran after the stop returned"
        );

        gate.start().expect("a start off the drive thread");
        wait_until("the drive to resume", || {
            polls.load(Ordering::SeqCst) > frozen
        });
        done.store(true, Ordering::SeqCst);
        drive.join().expect("the drive thread");
    }

    /// Every callback runs on the drive thread, so a stop or a start made there
    /// would wait for itself: both are refused and change nothing.
    #[test]
    fn a_stop_or_a_start_on_the_drive_thread_is_refused_and_changes_nothing() {
        let gate = Arc::new(ReadGate::new(true));
        gate.mark_opened();
        let (tx, rx) = mpsc::channel();
        // On a thread of its own: a stop that waited for itself would never return,
        // and that must read as a failed test rather than a hung one.
        let gate_in = gate.clone();
        std::thread::spawn(move || {
            runtime().block_on(Pausable::new(gate_in.clone(), async move {
                let stop = gate_in.stop();
                let start = gate_in.start();
                let _ = tx.send((stop, start, gate_in.is_running()));
            }));
        });
        let seen = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("a stop on the drive thread waited for itself");
        assert_eq!(
            seen,
            (Err(CalledFromReadTask), Err(CalledFromReadTask), true),
            "a stop and a start on the drive thread must be refused, leaving the task running"
        );
    }

    /// A drive thread that is idle -- nothing to read, no timer due, which is where
    /// a session spends nearly all its time -- is woken by the stop and parks, so
    /// the stop returns. A gate that only set the flag would leave it asleep.
    #[test]
    fn a_stop_reaches_a_drive_that_is_idle() {
        let gate = Arc::new(ReadGate::new(true));
        gate.mark_opened();
        let polled = Arc::new(AtomicBool::new(false));
        let polled_in = polled.clone();
        let release = Arc::new(Notify::new());
        let release_in = release.clone();
        let drive = {
            let gate = gate.clone();
            std::thread::spawn(move || {
                runtime().block_on(Pausable::new(gate, async move {
                    polled_in.store(true, Ordering::SeqCst);
                    release_in.notified().await;
                }));
            })
        };
        wait_until("the drive's first poll", || polled.load(Ordering::SeqCst));

        stop_within_five_seconds(&gate);

        // Let the drive end, so its thread can be joined.
        gate.start().expect("a start off the drive thread");
        release.notify_one();
        drive.join().expect("the drive thread");
    }

    /// A drive that has ended has nobody left to park, so a stop made afterwards
    /// must not wait for it.
    #[test]
    fn a_stop_does_not_wait_for_a_drive_that_is_gone() {
        let gate = Arc::new(ReadGate::new(true));
        gate.mark_opened();
        runtime().block_on(Pausable::new(gate.clone(), async {}));
        stop_within_five_seconds(&gate);
    }

    /// A stop waits for EVERY gated future of the session, not for one of them: once each
    /// face is a task of its own, callbacks run on several threads. Two futures on threads
    /// of their own are each inside a step that blocks, the second for three times as long
    /// as the first; the stop made while both are in flight returns only when both are over,
    /// and after it neither runs until a start.
    #[test]
    fn a_stop_waits_for_every_gated_task() {
        let gate = Arc::new(ReadGate::new(true));
        gate.mark_opened();
        let done = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let in_flight = [
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ];
        let steps_ms = [40u64, 120];
        let drives: Vec<_> = (0..2)
            .map(|i| {
                let (gate, polls, done, in_flight) = (
                    gate.clone(),
                    polls.clone(),
                    done.clone(),
                    in_flight[i].clone(),
                );
                let step = steps_ms[i];
                std::thread::spawn(move || {
                    runtime().block_on(Pausable::new(gate, async move {
                        while !done.load(Ordering::SeqCst) {
                            in_flight.store(true, Ordering::SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(step));
                            polls.fetch_add(1, Ordering::SeqCst);
                            in_flight.store(false, Ordering::SeqCst);
                            tokio::task::yield_now().await;
                        }
                    }));
                })
            })
            .collect();

        wait_until("both steps in flight", || {
            in_flight[0].load(Ordering::SeqCst) && in_flight[1].load(Ordering::SeqCst)
        });
        stop_within_five_seconds(&gate);
        assert!(
            !in_flight[0].load(Ordering::SeqCst) && !in_flight[1].load(Ordering::SeqCst),
            "the stop returned while a step of one of the futures was still running"
        );
        let frozen = polls.load(Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            polls.load(Ordering::SeqCst),
            frozen,
            "a future ran after the stop returned"
        );

        gate.start().expect("a start off a callback");
        wait_until("the futures to resume", || {
            polls.load(Ordering::SeqCst) > frozen
        });
        done.store(true, Ordering::SeqCst);
        for drive in drives {
            drive.join().expect("a drive thread");
        }
    }

    /// "Inside a callback" is a property of ONE gate: a callback of one session may stop
    /// another session, which waits for that session's futures and not for itself.
    #[test]
    fn a_callback_of_one_session_may_stop_another() {
        let first = Arc::new(ReadGate::new(true));
        first.mark_opened();
        let second = Arc::new(ReadGate::new(true));
        second.mark_opened();
        let (tx, rx) = mpsc::channel();
        let (first_in, second_in) = (first.clone(), second.clone());
        std::thread::spawn(move || {
            runtime().block_on(Pausable::new(first_in, async move {
                let _ = tx.send((second_in.stop(), second_in.is_running()));
            }));
        });
        let seen = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("a stop of another session from a callback did not return");
        assert_eq!(
            seen,
            (Ok(()), false),
            "a callback of one session is not a callback of the other"
        );
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|text| (*text).to_owned()).collect()
    }

    /// R3073 -- scouting does not dial a locator the config states as an endpoint, and keeps the
    /// rest of the node's locators: the stated endpoint has a schedule of its own, and a second
    /// link to the same node is refused by it (one link per node), which sent the endpoint back to
    /// its retry schedule and the open through `scouting/delay`.
    #[test]
    fn scouting_does_not_dial_a_locator_the_config_states() {
        let configured = strings(&["tcp/127.0.0.1:7447"]);
        // Only the stated one: nothing is left, and the node is ignored.
        assert!(
            scouted_locators_to_dial(&configured, &strings(&["tcp/127.0.0.1:7447"])).is_empty()
        );
        // Another of the node's locators stays a way in.
        assert_eq!(
            scouted_locators_to_dial(
                &configured,
                &strings(&["tcp/127.0.0.1:7447", "tcp/10.0.0.7:7447"])
            ),
            strings(&["tcp/10.0.0.7:7447"])
        );
        // Nothing stated: nothing is removed.
        assert_eq!(
            scouted_locators_to_dial(&[], &strings(&["tcp/127.0.0.1:7447"])),
            strings(&["tcp/127.0.0.1:7447"])
        );
    }

    /// An endpoint's `#` configuration tail is not part of its locator, and its `?` metadata is:
    /// upstream's `to_locator` drops the first and keeps the second, and a scouted locator has
    /// no tail to begin with.
    #[test]
    fn an_endpoints_tail_is_not_its_locator_and_its_metadata_is() {
        assert_eq!(endpoint_locator("tcp/127.0.0.1:7447"), "tcp/127.0.0.1:7447");
        assert_eq!(
            endpoint_locator("tcp/127.0.0.1:7447#iface=lo"),
            "tcp/127.0.0.1:7447"
        );
        assert_eq!(
            endpoint_locator("udp/127.0.0.1:7447?rel=1#iface=lo"),
            "udp/127.0.0.1:7447?rel=1"
        );
        let with_tail = strings(&["tcp/127.0.0.1:7447#retry_period_init_ms=100"]);
        assert!(scouted_locators_to_dial(&with_tail, &strings(&["tcp/127.0.0.1:7447"])).is_empty());
        // Metadata makes it another locator: the reliable and unreliable links of one address.
        let reliable = strings(&["udp/127.0.0.1:7447?rel=1"]);
        assert_eq!(
            scouted_locators_to_dial(&reliable, &strings(&["udp/127.0.0.1:7447"])),
            strings(&["udp/127.0.0.1:7447"])
        );
    }

    /// The stance of a pico-shaped peer, as `wz-capi-pico` opens one.
    fn peer_stance() -> OpenStance {
        OpenStance {
            tx_queue: TxQueueConf::pico(),
            batch_size: DEFAULT_BATCH_SIZE,
            offer: SessionOffer::universal(),
            zid: None,
            start_read_task: true,
            timestamping: TimestampingEnabled::default(),
            shm_clients: crate::faces::no_shm_clients(),
            local_delivery: LocalDeliveryDrain::DriveTask,
            scouting: None,
            initial_interest: true,
            gossip: None,
            listen_phase: ListenPhase::SHIPPED,
            face_drive: FaceDrive::Serial,
        }
    }

    fn open_peer(connect: Vec<String>, listen: Vec<String>) -> Result<SessionState, OpenError> {
        open_blocking(
            connect,
            listen,
            CapiTlsConfig::default(),
            WhatAmI::Peer,
            DialPhase::ONCE,
            peer_stance(),
        )
    }

    /// A caller's first call after `z_open` finds the peer the open dialled.
    ///
    /// The open is released when the link has connected, and the face is registered by a
    /// task of the drive thread a moment after: a `z_get` issued on the calling thread
    /// straight after the open fans over the registry, found it empty, completed with no
    /// query on the wire, and the peer's queryable waited for ever. This opens a dialling
    /// peer against a listening one and reads the registry on the calling thread the
    /// instant the open returns, over many opens at once; before the open waited for the
    /// registration it read an empty registry on 1160 of 1200 opens. A C caller's own
    /// thread starts and its own calls take longer than that read, which is why the hang it
    /// caused was one run in a hundred and not one in one.
    ///
    /// Each round's port is one no other round in this process was given, and the face is
    /// checked to be to THIS round's listener. A port picked by binding and letting go can be
    /// handed to two rounds at once. Where the second listener's bind is refused (Linux) that
    /// round retries; on Windows both binds succeed, because a wz listener sets SO_REUSEADDR as
    /// upstream's does and that option lets a second socket bind a port a live listener holds.
    /// A dial can then be accepted by the other round's listener, whose teardown takes the face
    /// down before this round reads. The open is released only once its face is registered, so
    /// a face that left the registry is the route to an empty read, and that is the reading of
    /// the 1 of 1200 hosted Platform run 38013268899 counted on Windows. A face to another
    /// listener is counted apart, so a shared port that survives is reported as what it is.
    #[test]
    fn an_open_that_dialled_a_peer_returns_with_its_face_in_the_registry() {
        const THREADS: usize = 8;
        const ROUNDS_PER_THREAD: usize = 150;
        // Eight rounds at a time, each a listener and a dialler with a runtime apiece, hold
        // hundreds of descriptors at once: more than the 1024 a build host's shell allows, where
        // the open fails with `Too many open files` and the test reports the host's setting as
        // a failed dial. The process asks for what it needs.
        let limit = wz_runtime_tokio_test_support::raise_open_file_limit(65_536);
        assert!(
            limit >= 4096,
            "the open-file limit is {limit}, too low for {THREADS} concurrent rounds"
        );
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                std::thread::spawn(|| {
                    let (mut empty, mut foreign) = (0usize, 0usize);
                    // What a face that is neither empty nor ours looked like: the round's
                    // endpoint, the listener's id and the id each face reported, so a
                    // hosted failure says which of "to another listener" and "ours, but
                    // not yet identified" it was.
                    let mut sightings: Vec<String> = Vec::new();
                    for _ in 0..ROUNDS_PER_THREAD {
                        // A port the listener's own bind chooses would need the listen role to
                        // report it. This one no other caller in the process was given; a process
                        // outside this one can still take it first, and that round is retried.
                        let (listener, endpoint) = loop {
                            let endpoint = format!(
                                "tcp/127.0.0.1:{}",
                                wz_runtime_tokio_test_support::free_port()
                            );
                            if let Ok(listener) = open_peer(Vec::new(), vec![endpoint.clone()]) {
                                break (listener, endpoint);
                            }
                        };
                        let dialler =
                            open_peer(vec![endpoint.clone()], Vec::new()).expect("the dial opens");
                        let faces = dialler.shared.face_sessions_with_wake();
                        let ours = listener.zid();
                        if faces.is_empty() {
                            empty += 1;
                        } else if !faces.iter().any(|(session, _)| {
                            // `ours` is the sixteen bytes `z_info_zid` reports and the wire
                            // carries the id trimmed: the same id, in two spellings.
                            is_expected_peer(session.actions().peer_zid().as_deref(), &ours[..])
                        }) {
                            foreign += 1;
                            if sightings.len() < 3 {
                                let seen: Vec<String> = faces
                                    .iter()
                                    .map(|(session, _)| {
                                        format!("{:02x?}", session.actions().peer_zid())
                                    })
                                    .collect();
                                sightings.push(format!(
                                    "{endpoint}: listener {:02x?}, faces {seen:?}",
                                    &ours[..]
                                ));
                            }
                        }
                        drop(dialler);
                        drop(listener);
                    }
                    (empty, foreign, sightings)
                })
            })
            .collect();
        let (empty, foreign, sightings) = workers
            .into_iter()
            .map(|worker| worker.join().expect("a worker panicked"))
            .fold((0, 0, Vec::new()), |(e, f, mut seen), (we, wf, ws)| {
                seen.extend(ws);
                (e + we, f + wf, seen)
            });
        let opens = THREADS * ROUNDS_PER_THREAD;
        assert_eq!(
            empty, 0,
            "{empty} of {opens} opens returned before the face they dialled was in the registry"
        );
        assert_eq!(
            foreign, 0,
            "{foreign} of {opens} dials were accepted by another round's listener on the same port; first sightings: {sightings:#?}"
        );
    }
}

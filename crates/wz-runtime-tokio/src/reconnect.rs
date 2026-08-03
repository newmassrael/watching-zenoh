// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A4b (session-reconnect) — the re-dial + re-handshake supervisor.
//!
//! zenoh-pico `Z_FEATURE_AUTO_RECONNECT` parity, runtime side. pico's shape
//! (`src/net/session.c` `_z_client_reopen_task_fn` + the
//! `_zp_unicast_failed_result` trigger in `src/transport/unicast/lease.c`):
//! when the transport dies under an established client session, the session
//! struct survives, a reopen task re-runs `_z_open` against the retained
//! config — retrying every 1s on transient failures, giving up on permanent
//! ones — and on success replays the declaration cache before resuming the
//! suspended transport tasks.
//!
//! The wz mirror maps each half onto the existing seams:
//!
//! - the surviving `_z_session_t` = the [`SessionLinkActions`] bundle (and
//!   every `Session` / handle clone over it), wired at first open over a
//!   [`SwappableLink`] so the supervisor can re-point it at the re-dialed
//!   link ([`SwappableLink::swap`] = pico replacing `_z_session_t._tp`
//!   under the transport mutex);
//! - the reopen task = [`ReconnectingSession::drive`]'s reconnect loop:
//!   `reset_for_reopen` (pico's fresh `_z_transport_t`) → re-dial the
//!   retained [`ReconnectLocator`] → swap → the same [`initiator_open`]
//!   bring-up the first open used (fresh engine over the same actions) →
//!   [`SessionLinkActions::replay_declarations`] (pico's declaration-cache
//!   walk) → resume the steady-state loop;
//! - the suspended-sibling-tasks resume = re-entering
//!   [`drive_session_until_terminal`] with the fresh engine + inbound (wz
//!   runs one drive loop where pico runs read/lease/keepalive tasks).
//!
//! Local close is the caller's signal, not an inference: pico's reopen task
//! exits when `z_close` emptied the session config; the wz supervisor checks
//! the caller's `stop` flag at each loop boundary (set it, then close the
//! session — e.g. `send_close_with_reason` — so the drive loop terminates
//! and observes the flag).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use wz_runtime_core::TimeSource;
use wz_session_core::driver_loop::IterationEvent;
// R311pw — the retained re-dial target is a [`ReconnectLocator`] (the
// reconnectable subset: numeric `Ip` | DNS `Named`, both IP-family
// connection-oriented). pico's `Z_FEATURE_AUTO_RECONNECT` is a client
// TCP/UDP/TLS/WS re-open path (R311oe — TLS/WS ride TCP, so they are `Ip` /
// `Named` arms too); serial is a point-to-point tty with no reopen-task model
// and is excluded at the `ReconnectLocator` narrowing boundary, not here. The
// retained locator widens back to `AnyLocator` (`.into()`) at each
// `dial_locator` call site — a `Named` arm re-resolves the host on EVERY
// attempt (DNS failover), where the prior IP-only `ParsedLocator` could not
// reconnect a hostname `--connect` at all (the R311ps dial/reconnect
// asymmetry this closes).
// R311pw — re-export the reconnectable-locator type (and its narrowing
// rejection) so a caller gets `open_session_with_reconnect` and its parameter
// type from one path; the supervisor module is where the reconnect API lives.
pub use wz_session_core::reconnect::{NotReconnectable, ReconnectLocator};
use wz_session_core::reconnect::{ReplayDeclarationsError, SwappableLink};
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;

use crate::runtime_impl::{TokioRuntime, TokioTime};
use crate::session::TokioSession;
use crate::session_glue::{
    drive_session_until_terminal, new_session_actions, BoxedLinkDriver, DriverOutcome,
    SessionLinkActions,
};
use crate::session_open::{
    dial_locator, initiator_open, plan_endpoint, wire_dialed_link, DialConfig, OpenError,
    OpenedSession,
};
use crate::writer_queue::WriterHandle;

/// Reconnect retry policy. The defaults are the pico literals:
/// `_z_client_reopen_task_fn` re-arms itself with
/// `_z_fut_fn_result_wake_up_after(1000)` on a transient failure and never
/// counts attempts (the session retries until closed or a permanent error).
#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    /// Delay between failed reopen attempts, milliseconds.
    pub retry_delay_ms: u64,
    /// Attempt cap per link loss; `None` = unbounded (pico default).
    pub max_attempts: Option<u32>,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            retry_delay_ms: 1000,
            max_attempts: None,
        }
    }
}

/// Why a reconnect could not restore the session.
#[derive(Debug)]
pub enum ReconnectError {
    /// The reopen attempt failed with a permanent [`OpenError`] (or the
    /// attempt cap elapsed on a transient one).
    Open(OpenError),
    /// The post-handshake declaration replay rejected — an invariant
    /// breach (see [`ReplayDeclarationsError`]); the supervisor does not
    /// retry it because identical inputs would reject identically.
    Replay(ReplayDeclarationsError),
}

/// How [`ReconnectingSession::drive`] ended.
#[derive(Debug)]
pub enum ReconnectDriveOutcome {
    /// The caller's `stop` flag was observed at a loop boundary after the
    /// current connection terminated — the local-close path (pico: reopen
    /// task exits on emptied session config).
    Stopped,
    /// Reconnection was abandoned: a permanent open error, an exhausted
    /// attempt cap, or a replay invariant breach. `attempts` counts the
    /// reopen tries for the final link loss. F6 — the supervisor
    /// survives (`drive` borrows): data sends over the surviving bundle
    /// reject typed (`TransportUnavailable`, the F2 gate) rather than
    /// silently vanish, and calling [`ReconnectingSession::drive`]
    /// again resumes the reopen loop at the caller's pace.
    GaveUp { attempts: u32, last: ReconnectError },
    /// The per-connection `max_iters` test guard elapsed inside the
    /// steady-state loop (production passes `None`).
    IterationLimit,
}

/// A unicast Initiator session whose link is supervised for reconnect: the
/// actions bundle emits through a [`SwappableLink`], and [`Self::drive`]
/// re-dials + re-handshakes + replays declarations whenever the steady-state
/// loop terminates without the caller's stop signal.
pub struct ReconnectingSession {
    actions: Arc<SessionLinkActions>,
    swappable: Arc<SwappableLink<TokioRuntime>>,
    locator: ReconnectLocator,
    /// R311oe — the dial config RETAINED across reconnects (taken by value at
    /// open). A `tls/...` re-dial needs the same client config + server name
    /// the first dial used; cert-free transports hold a default here. Struct
    /// always carries it (only `DialConfig`'s tls field is cfg-gated), so the
    /// reconnect supervisor is signature-stable across the tls toggle.
    dial_config: DialConfig,
    policy: ReconnectPolicy,
    open_max_iters: Option<usize>,
    tick_interval_ms: u64,
    opened: OpenedSession,
    reconnects: u32,
    /// R311y521 — the session whose liveliness registry must be flushed when
    /// the link dies, if the caller opted in via
    /// [`ReconnectingSession::set_liveliness_flush`].
    ///
    /// `Option`, and set by a builder rather than a constructor parameter, on
    /// purpose: `open_session_with_reconnect` and its string-taking sibling are
    /// pinned public entry points, and a session with no liveliness subscriber
    /// has nothing to flush. Widening beside them keeps every existing caller
    /// compiling unchanged.
    liveliness_session: Option<TokioSession>,
}

/// R311py — the handles [`ReconnectingSession::into_teardown`] hands back: the
/// surviving [`SessionLinkActions`] bundle (the last sink clone — the writer
/// task's sender lives behind it) and the writer-task join handle of the last
/// established connection. A named struct rather than a bare tuple so a caller
/// that only needs one field (e.g. discards `actions` because it already holds
/// its own clone) reads self-documenting at the destructure.
pub struct ReconnectTeardown {
    pub actions: Arc<SessionLinkActions>,
    pub writer_handle: WriterHandle,
}

impl ReconnectingSession {
    /// R311y521 — opt in to the pico link-loss liveliness flush: when the
    /// supervised link dies, every remote token this observer learned is
    /// flushed and each matching subscriber gets a `Delete`.
    ///
    /// Opt-IN rather than automatic because the supervisor cannot reach the
    /// observer on its own — the observer is the caller's, built alongside the
    /// `Session` over the same actions bundle. A caller that skips this keeps
    /// the pre-R311y521 behaviour, which is why the production path
    /// (`wz-ap-demo`) calls it.
    /// A SETTER, not a consuming builder, because the session is typically
    /// built AFTER the supervisor: the link is opened first and the `Session`
    /// is constructed over the resulting actions bundle (that is the order
    /// `wz-ap-demo` has). A `mut self` builder would force the caller to unbox
    /// and rebuild.
    ///
    /// Takes the SESSION, not the observer, and R311y522 is why: flushing the
    /// registry only STAGES the Deletes on the session's deferred-fire queue
    /// (R311lg), and delivering them needs
    /// [`TokioSession::drain_deferred_fires`], which lives on the session. The
    /// observer alone cannot deliver anything.
    pub fn set_liveliness_flush(&mut self, session: TokioSession) {
        self.liveliness_session = Some(session);
    }

    /// The shared actions bundle — the surviving half across reconnects.
    /// Callers build their `Session` / handles over this exactly as with a
    /// plain [`crate::session_open::connect_and_open_session`] result.
    pub fn actions(&self) -> &Arc<SessionLinkActions> {
        &self.actions
    }

    /// Number of successful reconnects performed by [`Self::drive`] so far
    /// (0 until the first link loss is survived).
    pub fn reconnects(&self) -> u32 {
        self.reconnects
    }

    /// R311pw — consume the supervisor into the graceful-teardown handles a
    /// caller needs after [`Self::drive`] returns: the surviving
    /// [`SessionLinkActions`] bundle and the writer-task join handle of the
    /// LAST ESTABLISHED connection. The caller feeds these into its existing
    /// teardown sequence (drop liveliness tokens → enqueue `Close` → drop the
    /// last actions clone → drain the writer), identical to the one-shot
    /// [`connect_and_open_session`] path — the supervisor adds no teardown
    /// shape of its own, it just unwraps what it encapsulated. (R311py — returns
    /// a named [`ReconnectTeardown`] rather than a bare tuple so the call site
    /// reads self-documenting.)
    ///
    /// Dropping the supervisor here releases the dead connection's engine +
    /// inbound half and the supervisor's own [`SwappableLink`] handle; the
    /// returned `actions` still holds the last sink clone (the writer task's
    /// `mpsc` sender lives behind it), so the caller's `drop(actions)` remains
    /// "the last sender by construction" and the writer drains to exit exactly
    /// as the non-supervised path's teardown does.
    ///
    /// CONTRACT on a [`GaveUp`](ReconnectDriveOutcome::GaveUp) outcome (R311py,
    /// review finding): `writer_handle` is the writer of the last connection
    /// that reached Established — NOT the half-open link a failed reopen left in
    /// the [`SwappableLink`]. That is correct, not a mismatch: a reopen that
    /// dialed but failed the handshake never reached Established, so it carries
    /// no session and has no graceful `Close` to drain — its orphaned writer
    /// task exits when the final `actions` drop releases the swapped-in sink.
    /// The teardown's writer-drain on a `GaveUp` is therefore a degenerate
    /// (immediately-returning) drain over the prior, already-closed link, which
    /// is the correct behaviour for an abandoned session with no live peer.
    ///
    /// [`connect_and_open_session`]: crate::session_open::connect_and_open_session
    pub fn into_teardown(self) -> ReconnectTeardown {
        // Destructure so the engine + inbound half + swappable drop here; keep
        // the surviving actions bundle + the last-established writer-task handle.
        let ReconnectingSession {
            actions, opened, ..
        } = self;
        ReconnectTeardown {
            actions,
            writer_handle: opened.writer_handle,
        }
    }

    /// One reopen attempt: re-dial the retained locator, swap the fresh
    /// outbound into the [`SwappableLink`] (dropping the dead sink closes
    /// the old writer channel, so the orphaned writer task exits on its
    /// own — there is no tail worth draining to a dead link), build a
    /// fresh engine over the SAME actions bundle, and re-run the shared
    /// open handshake loop. The wz body of pico's `_z_open` re-run inside
    /// `_z_client_reopen_task_fn`.
    async fn open_attempt(&self, clock: TokioTime) -> Result<OpenedSession, OpenError> {
        // R311oe — re-dial with the RETAINED DialConfig, not a fresh default:
        // a TLS session's reconnect needs the same client config + server name
        // the first dial used, so the supervisor stored it at open (pico
        // retains the session config in its reopen task). Cert-free transports
        // (tcp/udp) hold a default config here, so this stays behaviour-
        // preserving for them.
        let dialed = dial_locator(self.locator.clone().into(), &self.dial_config)
            .await
            .map_err(OpenError::Dial)?;
        let (inbound, outbound, writer_handle) = wire_dialed_link(dialed);
        let old = self.swappable.swap(outbound);
        drop(old);
        // R311ju — engine build + Initiator activation + open loop live once
        // in `initiator_open` (shared with the first open), so the
        // protocol-critical activation order cannot drift between the dial
        // path and the reopen path.
        initiator_open(
            inbound,
            self.actions.clone(),
            writer_handle,
            clock,
            self.open_max_iters,
            self.tick_interval_ms,
        )
        .await
    }

    /// Drive the session until the caller stops it or reconnection is
    /// abandoned. Runs [`drive_session_until_terminal`] over the current
    /// connection; on a terminal without `stop`, enters the reopen loop
    /// (pico `_z_client_reopen_task_fn`): per attempt —
    /// [`SessionLinkActions::reset_for_reopen`], re-dial + re-handshake
    /// ([`Self::open_attempt`]), then
    /// [`SessionLinkActions::replay_declarations`] — sleeping
    /// `policy.retry_delay_ms` between transient failures
    /// ([`Self::open_error_is_transient`]) and giving up on permanent
    /// ones.
    ///
    /// `stop` is checked at loop boundaries only: to close locally, set it
    /// and then terminate the connection (e.g.
    /// `SessionLinkActions::send_close_with_reason` + peer/link teardown)
    /// so the steady loop returns. Mirrors pico, where `z_close` empties
    /// the session config and the reopen task observes that at its next
    /// wake-up.
    ///
    /// F6 — borrows rather than consumes: after `drive` returns the
    /// caller still holds the supervisor, so the
    /// [`reconnects`](Self::reconnects) count and the
    /// [`actions`](Self::actions) bundle stay observable past
    /// termination, and a [`GaveUp`](ReconnectDriveOutcome::GaveUp)
    /// outcome can be RESUMED by calling `drive` again (the dead
    /// connection's engine is already terminal, so the next call drops
    /// straight into the reopen loop — caller-paced retry beyond the
    /// policy cap). While abandoned, every data send over the bundle
    /// rejects typed (`SendWireError::TransportUnavailable`, the F2
    /// gate) — handles built over the session are inert, not silently
    /// lossy.
    pub async fn drive<F>(
        &mut self,
        timeouts: &SessionTimeouts,
        stop: &AtomicBool,
        max_iters_per_connection: Option<usize>,
        mut on_event: F,
    ) -> ReconnectDriveOutcome
    where
        F: FnMut(IterationEvent<'_>),
    {
        loop {
            let clock = self.opened.clock;
            let outcome = drive_session_until_terminal(
                &mut self.opened.inbound,
                &self.actions,
                &mut self.opened.engine,
                max_iters_per_connection,
                &clock,
                timeouts,
                &mut on_event,
            )
            .await;
            match outcome {
                DriverOutcome::IterationLimit => return ReconnectDriveOutcome::IterationLimit,
                DriverOutcome::Terminated => {
                    if stop.load(Ordering::Acquire) {
                        return ReconnectDriveOutcome::Stopped;
                    }
                    // The dead connection (`self.opened`) is replaced on
                    // reopen success: its outbound sink is swapped out
                    // inside `open_attempt` (the orphaned writer task exits
                    // on channel close), and the stale inbound half +
                    // engine drop at the reassignment below.
                    let mut attempts: u32 = 0;
                    self.opened = loop {
                        if stop.load(Ordering::Acquire) {
                            return ReconnectDriveOutcome::Stopped;
                        }
                        attempts += 1;
                        // R311y521 — the link is gone, so every remote
                        // liveliness token it announced is gone with it and no
                        // UndeclToken can ever arrive for one (the link that
                        // would carry it is what died). Tell the subscribers
                        // BEFORE the reset, mirroring pico's ordering: the
                        // flush rides transport failure
                        // (`_zp_unicast_failed_result`), ahead of any reopen.
                        if let Some(session) = &self.liveliness_session {
                            let staged = match session.observer().lock() {
                                Ok(mut o) => o.flush_liveliness_on_link_loss(),
                                // A panicking sink poisons the mutex; recover
                                // rather than leak the whole registry, matching
                                // every other shutdown path in this crate.
                                Err(poisoned) => {
                                    poisoned.into_inner().flush_liveliness_on_link_loss()
                                }
                            };
                            if staged > 0 {
                                // R311y522 — the flush only STAGES on the
                                // deferred-fire queue; the drive loop is what
                                // normally drains it, and it has just returned.
                                // Without this the Deletes reach the
                                // application late (only if some other periodic
                                // sweeper happens to exist) or never.
                                session.drain_deferred_fires();
                                log::info!(
                                    "wz reconnect: link lost; delivered {staged} remote \
                                     liveliness token(s) as Delete"
                                );
                            }
                        }
                        self.actions.reset_for_reopen();
                        match self.open_attempt(clock).await {
                            Ok(reopened) => break reopened,
                            Err(err) if Self::open_error_is_transient(&err) => {
                                let capped =
                                    self.policy.max_attempts.is_some_and(|max| attempts >= max);
                                if capped {
                                    return ReconnectDriveOutcome::GaveUp {
                                        attempts,
                                        last: ReconnectError::Open(err),
                                    };
                                }
                                clock.sleep(self.policy.retry_delay_ms).await;
                            }
                            Err(err) => {
                                return ReconnectDriveOutcome::GaveUp {
                                    attempts,
                                    last: ReconnectError::Open(err),
                                };
                            }
                        }
                    };
                    // pico parity: the reopen task replays the declaration
                    // cache right after `_z_open` succeeds; a replay reject
                    // is an invariant breach, not a retryable condition.
                    if let Err(err) = self.actions.replay_declarations() {
                        return ReconnectDriveOutcome::GaveUp {
                            attempts,
                            last: ReconnectError::Replay(err),
                        };
                    }
                    self.reconnects += 1;
                }
            }
        }
    }

    /// pico's transient set (`_z_client_reopen_task_fn` retries on
    /// `_Z_ERR_TRANSPORT_OPEN_FAILED` / `_Z_ERR_SCOUT_NO_RESULTS` /
    /// `_Z_ERR_TRANSPORT_TX_FAILED` / `_Z_ERR_TRANSPORT_RX_FAILED`,
    /// gives up on anything else). wz mapping: a dial failure, a link
    /// lost mid-handshake, a handshake timeout, and a pre-Established
    /// terminal (peer closed during the handshake) are all conditions a
    /// later attempt can outlive; a bad locator cannot succeed and the
    /// iteration-limit test guard must surface, so both give up.
    fn open_error_is_transient(err: &OpenError) -> bool {
        matches!(
            err,
            OpenError::Dial(_)
                | OpenError::LinkLost(_)
                | OpenError::HandshakeTimeout
                | OpenError::Terminal
        )
    }
}

/// Dial `locator` and bring up a unicast Initiator session whose link is
/// reconnect-supervised: the actions bundle is wired over a
/// [`SwappableLink`] from the start, so a later
/// [`ReconnectingSession::drive`] can replace the transport without
/// touching the bundle (or any `Session` / handle clone over it).
///
/// `locator` is a [`ReconnectLocator`] — the reconnectable subset (numeric
/// `Ip` | DNS `Named`). A caller with an [`AnyLocator`] from the parse seam
/// narrows it via [`ReconnectLocator::try_from`] (a `serial/...` endpoint is
/// rejected there: no reopen-task model). R311pw — a `Named` host is
/// RE-RESOLVED on every re-dial, so a hostname `--connect` reconnects and
/// follows the host's current address; the prior `ParsedLocator` parameter
/// admitted only numeric endpoints (the R311ps dial/reconnect asymmetry).
///
/// [`AnyLocator`]: wz_session_core::locator::AnyLocator
///
/// `dial_config` is RETAINED for the supervisor's lifetime (taken by value,
/// unlike the one-shot opens that borrow it): every reconnect re-dials with
/// the SAME config, so a `tls/...` session keeps the client config + server
/// name it first used (pico retains the session config in its reopen task).
/// Cert-free transports (tcp/udp) pass [`DialConfig::default`] (R311oe).
///
/// The INITIAL open does not retry — pico parity: `z_open` is the user's
/// call and surfaces its own error; `Z_FEATURE_AUTO_RECONNECT` only guards
/// an established session's transport death (`_zp_unicast_failed_result`
/// fires from the live read/lease tasks, never from `z_open` itself).
pub async fn open_session_with_reconnect(
    locator: ReconnectLocator,
    params: SessionInitParams,
    dial_config: DialConfig,
    clock: TokioTime,
    policy: ReconnectPolicy,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<ReconnectingSession, OpenError> {
    // R311oe — the dial config is RETAINED (moved into the supervisor below)
    // so every reconnect re-dials with it; borrow it for the initial dial.
    // R311pw — `locator` is the reconnectable subset (numeric `Ip` | DNS
    // `Named`); clone it for the initial dial (it widens to `AnyLocator` via
    // `.into()`) and move the original into the supervisor for the re-dials.
    let dialed = dial_locator(locator.clone().into(), &dial_config)
        .await
        .map_err(OpenError::Dial)?;
    let (inbound, outbound, writer_handle) = wire_dialed_link(dialed);
    let swappable = Arc::new(SwappableLink::<TokioRuntime>::new(outbound));
    let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = swappable.clone();
    let actions = new_session_actions(sink, params, clock);
    // R311ju — first open routes through the same shared `initiator_open`
    // body every reopen attempt uses (engine build + activation + open loop).
    let opened = initiator_open(
        inbound,
        actions,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await?;
    Ok(ReconnectingSession {
        actions: opened.actions.clone(),
        swappable,
        locator,
        dial_config,
        policy,
        open_max_iters: max_iters,
        tick_interval_ms,
        opened,
        reconnects: 0,
        liveliness_session: None,
    })
}

/// R311py — open a reconnect-supervised session from a `--connect`-style
/// STRING. The reconnect-path sibling of [`dial_endpoint`] (string → dialed
/// link) and [`accept_endpoint`] (string → accepted link): the single library
/// home of "turn a `--connect` string into a [`ReconnectingSession`]". It
/// reuses the SHARED [`plan_endpoint`] classifier (scheme-less `tcp/`
/// convenience included) so the dial / accept / reconnect paths parse a connect
/// string by ONE set of rules, then narrows the parsed [`AnyLocator`] to the
/// reconnectable subset via [`ReconnectLocator::try_from`] — a `serial/...`
/// endpoint is rejected as [`OpenError::NotReconnectable`] (typed, not a string;
/// pico `Z_FEATURE_AUTO_RECONNECT` is IP-family only), a malformed string as
/// [`OpenError::BadLocator`].
///
/// A consumer (e.g. wz-ap-demo's `--reconnect` Initiator) calls THIS rather than
/// hand-assembling `plan_endpoint` + `try_from` + [`open_session_with_reconnect`]
/// — the orchestration is library-owned, symmetric with the dial/accept seams,
/// so `plan_endpoint` need not be public.
///
/// [`dial_endpoint`]: crate::session_open::dial_endpoint
/// [`accept_endpoint`]: crate::session_open::accept_endpoint
/// [`AnyLocator`]: wz_session_core::locator::AnyLocator
pub async fn reconnect_endpoint(
    connect: &str,
    params: SessionInitParams,
    dial_config: DialConfig,
    clock: TokioTime,
    policy: ReconnectPolicy,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<ReconnectingSession, OpenError> {
    let locator =
        ReconnectLocator::try_from(plan_endpoint(connect).map_err(OpenError::BadLocator)?)
            .map_err(OpenError::NotReconnectable)?;
    open_session_with_reconnect(
        locator,
        params,
        dial_config,
        clock,
        policy,
        max_iters,
        tick_interval_ms,
    )
    .await
}

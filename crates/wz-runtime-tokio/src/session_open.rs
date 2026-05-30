// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311eu — mode-agnostic session-open orchestration over the R311et link
//! pipeline.
//!
//! [`dial_locator`] dispatches a [`ParsedLocator`]'s protocol to a raw
//! transport (the mode-agnostic seam: a discovered locator is dialed the
//! same way regardless of how scouting found it).
//! [`connect_and_open_session`] dials, splits the connection into the
//! [`crate::link_pipeline`] read/write halves, wires the unicast session FSM
//! in the Initiator role, and drives the inbound handshake to Established —
//! returning the live [`OpenedSession`] handles for the caller to run the
//! steady state via [`crate::session_glue::drive_session_until_terminal`].
//!
//! This is the reusable lib form of the open path wz-ap-demo's `runner.rs`
//! assembles inline; R311ev makes the demo consume it (removing the
//! duplication). R311ew wired the static scouting -> parse -> dial -> open
//! seam; R311ez generalises the dial to a transport union so a `udp/...`
//! locator opens a datagram session ([`crate::udp_pipeline`]) the same way
//! a `tcp/...` locator opens a stream session.

use std::io;
use std::sync::Arc;

use sce_rust_lua::LuaEngine;
use sce_rust_runtime::scripting::IScriptEngine;
use sce_rust_runtime::Engine;
use tokio::net::TcpStream;

use wz_runtime_core::TimeSource;
use wz_session_core::locator::{parse_locator, LocatorParseError, ParsedLocator, Proto};
use wz_session_core::scout_static::synth_static_locators;

use crate::link_pipeline::{dial_tcp, wire_tcp_stream, TcpReadDriver};
use crate::runtime_impl::{TokioJoinHandle, TokioTime};
use crate::session_fsm_unicast::{SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy};
use crate::session_glue::{
    install_session_actions, poll_and_dispatch_one, BoxedLinkDriver, CloseReason,
    DriverLoopOutcome, SessionInitParams, SessionLinkActions,
};
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, TxFrame};

#[cfg(feature = "transport-link-udp")]
use crate::udp_pipeline::{dial_udp, wire_udp_socket, UdpReadDriver};
#[cfg(feature = "transport-link-udp")]
use std::net::SocketAddr;
#[cfg(feature = "transport-link-udp")]
use tokio::net::UdpSocket;

/// Default cadence at which [`connect_and_open_session`] pumps the SCE
/// scheduler (`Engine::tick`) while waiting on the handshake. It bounds
/// only the *precision* of the open-deadline (a handshake timer fires
/// within `[delay, delay + DEFAULT_OPEN_TICK_MS]`), never the deadline
/// itself — the window durations are the SCXML's single source of truth
/// (`link.open_timeout` / `init_ack.timeout` / `open_ack.timeout`). 50ms
/// keeps the 2s/5s windows accurate to <3% while the inbound `poll_event`
/// races the tick so a frame still resolves the instant it arrives.
pub const DEFAULT_OPEN_TICK_MS: u64 = 50;

/// A dialed raw transport — the mode-agnostic dial seam's output, a union
/// spanning both protocols (R311ez). [`wire_dialed_link`] consumes it into
/// the uniform `(InboundLink, Arc<dyn BoxedLinkDriver>, writer-handle)`
/// triple regardless of which arm it carries, so [`connect_and_open_session`]
/// drives a TCP stream session and a UDP datagram session through one code
/// path.
pub enum DialedLink {
    /// A connected stream, split downstream via [`wire_tcp_stream`].
    Tcp(TcpStream),
    /// A bound datagram socket + its unicast peer, shared downstream via
    /// [`wire_udp_socket`].
    #[cfg(feature = "transport-link-udp")]
    Udp { socket: UdpSocket, peer: SocketAddr },
}

/// Dial a parsed locator to its raw transport — the mode-agnostic dial seam.
///
/// `Proto::Tcp` returns a connected [`TcpStream`] (split downstream by
/// [`wire_dialed_link`] via [`wire_tcp_stream`], per the R311et raw-dial
/// decision: the stream is dialed once and the split shape is chosen by the
/// consumer, not buried inside a unified driver).
///
/// `Proto::Udp` binds an ephemeral local socket targeting the locator's peer
/// ([`dial_udp`]) when the `transport-link-udp` feature is compiled in;
/// downstream [`wire_udp_socket`] shares it into the read/write drivers. With
/// the feature off, a `udp/...` locator surfaces a typed `Unsupported` error
/// rather than silently mis-dialing.
pub async fn dial_locator(locator: ParsedLocator) -> io::Result<DialedLink> {
    match locator.proto {
        Proto::Tcp => Ok(DialedLink::Tcp(dial_tcp(locator.addr).await?)),
        #[cfg(feature = "transport-link-udp")]
        Proto::Udp => Ok(DialedLink::Udp {
            socket: dial_udp(locator.addr).await?,
            peer: locator.addr,
        }),
        #[cfg(not(feature = "transport-link-udp"))]
        Proto::Udp => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "udp session-open requires the transport-link-udp feature",
        )),
    }
}

/// Inbound read driver of a dialed link — the transport union on the read
/// side, so [`OpenedSession`] carries one concrete type whether the locator
/// dialed a stream or a datagram socket (the `LinkDriver` trait uses
/// `async fn`, which is not dyn-compatible, so the union is an enum rather
/// than a `Box<dyn LinkDriver>`). [`poll_and_dispatch_one`] drives it
/// generically via the [`LinkDriver`] impl, which forwards each method to the
/// inner driver.
pub enum InboundLink {
    Tcp(TcpReadDriver),
    #[cfg(feature = "transport-link-udp")]
    Udp(UdpReadDriver),
}

impl LinkDriver for InboundLink {
    async fn open(&mut self) -> io::Result<()> {
        match self {
            InboundLink::Tcp(d) => d.open().await,
            #[cfg(feature = "transport-link-udp")]
            InboundLink::Udp(d) => d.open().await,
        }
    }

    async fn send(&mut self, frame: &TxFrame<'_>, reliability: Reliability) -> io::Result<()> {
        match self {
            InboundLink::Tcp(d) => d.send(frame, reliability).await,
            #[cfg(feature = "transport-link-udp")]
            InboundLink::Udp(d) => d.send(frame, reliability).await,
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        match self {
            InboundLink::Tcp(d) => d.close().await,
            #[cfg(feature = "transport-link-udp")]
            InboundLink::Udp(d) => d.close().await,
        }
    }

    async fn poll_event(&mut self) -> LinkEvent {
        match self {
            InboundLink::Tcp(d) => d.poll_event().await,
            #[cfg(feature = "transport-link-udp")]
            InboundLink::Udp(d) => d.poll_event().await,
        }
    }
}

/// Wire a [`DialedLink`] into the cooperating drivers the session FSM
/// consumes — the per-transport branch that converges on one shape: an
/// inbound [`InboundLink`] (`&mut LinkDriver` for the poll loop), an outbound
/// `Arc<dyn BoxedLinkDriver>` (`send_blocking` for the Lua actions), and the
/// writer-task join handle. TCP splits the stream ([`wire_tcp_stream`]); UDP
/// shares the socket ([`wire_udp_socket`]).
pub fn wire_dialed_link(
    dialed: DialedLink,
) -> (InboundLink, Arc<dyn BoxedLinkDriver>, TokioJoinHandle<()>) {
    match dialed {
        DialedLink::Tcp(stream) => {
            let (inbound, outbound, handle) = wire_tcp_stream(stream);
            (InboundLink::Tcp(inbound), outbound, handle)
        }
        #[cfg(feature = "transport-link-udp")]
        DialedLink::Udp { socket, peer } => {
            let (inbound, outbound, handle) = wire_udp_socket(socket, peer);
            (InboundLink::Udp(inbound), outbound, handle)
        }
    }
}

/// Live handles for a session brought up to Established by
/// [`connect_and_open_session`]. The caller continues the steady state by
/// threading `inbound` + `actions` + `engine` into
/// [`crate::session_glue::drive_session_until_terminal`], and awaits
/// `writer_handle` during teardown so a tail frame the FSM enqueues during
/// its final transition still drains to the peer. `clock` is the shared
/// monotonic epoch (Copy) the open phase used, returned so the steady-state
/// loop and any lease comparator stay on the same epoch.
pub struct OpenedSession {
    pub engine: Engine<SessionFsmUnicastPolicy>,
    pub actions: Arc<SessionLinkActions>,
    pub inbound: InboundLink,
    pub writer_handle: TokioJoinHandle<()>,
    pub clock: TokioTime,
}

/// Why a session did not reach Established.
#[derive(Debug)]
pub enum OpenError {
    /// The locator string did not parse into a typed endpoint (R311ew —
    /// surfaced by [`open_session_at`] / [`open_session_static`] when a
    /// scouting-supplied or configured locator is malformed).
    BadLocator(LocatorParseError),
    /// Dial failed (TCP connect refused, socket bind error), or the locator
    /// protocol is not compiled in (a `udp/...` locator with the
    /// `transport-link-udp` feature off surfaces a typed `Unsupported` here).
    Dial(io::Error),
    /// The link was lost mid-handshake (peer closed before OpenAck).
    LinkLost(LostCause),
    /// The FSM reached a terminal state before Established — e.g. a peer
    /// Close during the handshake.
    Terminal,
    /// A handshake timer fired before Established: the peer did not complete
    /// the handshake within the SCXML-declared window (`init_ack.timeout` /
    /// `open_ack.timeout`, 2s each; `link.open_timeout` 5s). The SCE
    /// scheduler fires the timer once [`connect_and_open_session`]'s tick
    /// pump advances past the deadline, driving the FSM to `Closing`.
    /// Distinguished from [`Self::Terminal`] via the close-reason trace: a
    /// timeout transition runs `set_close_reason_generic` (so
    /// `set_close_reason_count >= 1` with `CloseReason::Generic`), whereas a
    /// peer Close / link loss reaches `Closed` without a close-reason action.
    HandshakeTimeout,
    /// The bounded iteration budget elapsed before Established (test guard;
    /// production passes `None`).
    IterationLimit,
    /// Every configured static locator failed (parse / dial / handshake) —
    /// the static-mode "configured locators are wrong / unreachable"
    /// diagnostic (docs/scouting-fsm.md §2.4.3 reason #1). Only returned by
    /// [`open_session_static`].
    NoReachableLocator,
}

/// Build the session action layer + SCE engine for an open path, ready for
/// role activation. Shared by [`connect_and_open_session`] (Initiator) and
/// [`accept_and_open_session`] (Accepting): both wire the same
/// [`SessionLinkActions`] + Lua-bound [`SessionFsmUnicastPolicy`] engine and
/// differ only in the role-start event they dispatch afterwards.
fn wire_session_engine(
    outbound: Arc<dyn BoxedLinkDriver>,
    params: SessionInitParams,
    clock: TokioTime,
) -> (Arc<SessionLinkActions>, Engine<SessionFsmUnicastPolicy>) {
    let actions = SessionLinkActions::new(outbound, params, clock);
    let script_engine: Arc<dyn IScriptEngine> = Arc::new(LuaEngine::new());
    install_session_actions(actions.clone(), &script_engine);
    let mut engine: Engine<SessionFsmUnicastPolicy> =
        Engine::new(SessionFsmUnicastPolicy::new(script_engine));
    engine.initialize();
    (actions, engine)
}

/// Drive an already-activated session FSM to Established, bounded by the
/// FSM's own handshake timers (R311fa). The role-agnostic open loop shared by
/// both open paths: the caller wires the link + engine and dispatches the
/// role-start event, then this races the cancel-safe inbound poll against a
/// `tick_interval_ms` cadence that pumps `Engine::tick` so an elapsed SCXML
/// `<send delay>` fires its transition — the Initiator's `init_ack.timeout` /
/// `open_ack.timeout` (2s) / `link.open_timeout` (5s), and the Accepting
/// side's `accepting.inactivity_timeout` (1s, R311fb). A frame that arrives
/// first resolves the handshake without waiting for the next tick; the losing
/// `select!` branch is cancelled, safe because `poll_and_dispatch_one`'s only
/// await is `poll_event`, whose partial-read state lives in the driver's
/// `ReadState`.
///
/// Terminal mapping is role-agnostic. A pre-Established terminal reached via a
/// timeout transition that ran `set_close_reason_generic` (the Initiator's
/// Closing path) surfaces as [`OpenError::HandshakeTimeout`]; every other
/// pre-Established terminal surfaces as [`OpenError::Terminal`] — a peer
/// Close, a link loss to Closed, and the Accepting side's
/// `accepting.inactivity_timeout` -> Closed (which runs no close-reason action
/// per §2.7 anti-amplification). So a timed-out accept is reported as
/// `Terminal`, intentionally indistinguishable from a peer close: the silent
/// drop spends no Close frame on a possibly-spoofed peer.
async fn drive_open_loop(
    mut inbound: InboundLink,
    actions: Arc<SessionLinkActions>,
    mut engine: Engine<SessionFsmUnicastPolicy>,
    writer_handle: TokioJoinHandle<()>,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let mut iter: usize = 0;
    loop {
        let trace = actions.trace_snapshot();
        if trace.record_established_at >= 1 {
            return Ok(OpenedSession {
                engine,
                actions,
                inbound,
                writer_handle,
                clock,
            });
        }
        if engine.is_in_final_state() {
            // Pre-Established terminal. A handshake-timer transition on the
            // Initiator path ran `set_close_reason_generic` (count >= 1,
            // reason Generic); a peer Close / link loss / the silent accept
            // inactivity timeout reaches Closed without a close-reason action
            // (count == 0), so the Initiator timeout is distinguishable while
            // the accept timeout folds into Terminal (silent-drop by design).
            return Err(
                if trace.set_close_reason_count >= 1 && trace.close_reason == CloseReason::Generic {
                    OpenError::HandshakeTimeout
                } else {
                    OpenError::Terminal
                },
            );
        }
        if let Some(limit) = max_iters {
            if iter >= limit {
                return Err(OpenError::IterationLimit);
            }
            iter += 1;
        }
        // R311fa — race the cancel-safe inbound poll against a clock tick that
        // pumps the SCE scheduler so an elapsed handshake `<send delay>` fires
        // its FSM transition; a frame that arrives first resolves without
        // waiting for the next tick.
        tokio::select! {
            outcome = poll_and_dispatch_one(&mut inbound, &actions, &mut engine) => {
                if let DriverLoopOutcome::LinkLost(cause) = outcome {
                    return Err(OpenError::LinkLost(cause));
                }
            }
            _ = clock.sleep(tick_interval_ms) => {
                engine.tick();
            }
        }
    }
}

/// Dial `locator`, wire the connection into the link pipeline ([`DialedLink`]
/// -> [`wire_dialed_link`]: a stream splits into read/write halves, a
/// datagram socket is shared), wire the unicast session FSM in the Initiator
/// role, and drive the inbound handshake (peer InitAck -> OpenSyn -> peer
/// OpenAck) until the FSM records Established.
///
/// The handshake messages are transport-uniform — the only difference is
/// framing: TCP length-prefixes each through `StreamEnvelope`, UDP sends
/// one message per datagram (boundary == frame), and both decode through the
/// same `handle_inbound` path.
///
/// Wall-clock bounded by the FSM's own handshake timers (R311fa). The
/// inbound poll is raced in a `tokio::select!` against a `tick_interval_ms`
/// cadence that calls `Engine::tick`; once the SCE scheduler passes a
/// `<send delay>` deadline armed by the current handshake state
/// (`init_ack.timeout` / `open_ack.timeout`, 2s; `link.open_timeout`, 5s),
/// it fires the timer and the FSM transitions to `Closing` — surfaced here
/// as [`OpenError::HandshakeTimeout`]. So a peer that never answers no
/// longer hangs the loop (the prior `max_iters`-only bound was a test
/// guard, not a wall-clock deadline). The window durations are the SCXML's
/// single source of truth; `tick_interval_ms` only sets how finely the host
/// pumps the clock (see [`DEFAULT_OPEN_TICK_MS`]). `poll_and_dispatch_one`
/// is cancel-safe (partial reads live in `TcpReadDriver`'s `ReadState`), so
/// the tick branch can cancel an in-flight read without losing wire bytes.
///
/// The Initiator activation is `OutboundStart` (-> LinkOpening; the
/// `link_driver_open` action is a no-op since the stream is already
/// connected) + `LinkOpened` (-> SentInitSyn, which fires `send_init_syn` —
/// the first wire byte, enqueued on the outbound channel). This is the same
/// sequence wz-ap-demo's `activate_role` dispatches for the Initiator role.
///
/// Established is detected via the `record_established_at` action counter,
/// which fires on the Established onentry regardless of sub-state — so this
/// helper does not depend on the generated FSM state-enum shape.
///
/// `max_iters` bounds the inbound poll loop for test determinism;
/// production passes `None` and relies on the handshake-timer deadline
/// above. `tick_interval_ms` is the SCE-scheduler pump cadence
/// ([`DEFAULT_OPEN_TICK_MS`] for production).
pub async fn connect_and_open_session(
    locator: ParsedLocator,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let dialed = dial_locator(locator).await.map_err(OpenError::Dial)?;
    let (inbound, outbound, writer_handle) = wire_dialed_link(dialed);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);

    // Initiator activation -> SentInitSyn (send_init_syn enqueues InitSyn).
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);

    drive_open_loop(
        inbound,
        actions,
        engine,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// Bring up a session in the Accepting role from an already-accepted transport
/// — the listener half, symmetric to [`connect_and_open_session`]'s dial half.
///
/// The caller owns the listener and hands the accepted connection in as a
/// [`DialedLink`] (`DialedLink::Tcp(stream)` from a `TcpListener::accept`
/// result; the datagram acceptor is test-only). This wires it through the same
/// [`wire_dialed_link`] -> [`wire_session_engine`] path the dial side uses,
/// activates the FSM in the Accepting role (`inbound.start` ->
/// `Accepting.AwaitingInitSyn`), and drives the 4-way handshake (peer InitSyn
/// -> our InitAck -> peer OpenSyn -> our OpenAck) to Established.
///
/// Wall-clock bounded by the accept-side open-deadline (R311fb): the
/// `accepting.inactivity_timeout` armed on `AwaitingInitSyn` entry (1s, §2.5)
/// fires through the same `Engine::tick` pump as the Initiator timers, so a
/// peer that connects then goes silent no longer hangs the loop (closing the
/// R311fa carry #2 — the Initiator path was bounded, the acceptor was not).
/// The drop is silent (the transition targets `Closed`, no Close frame —
/// §2.7 anti-amplification) and therefore surfaces as [`OpenError::Terminal`],
/// not a distinct timeout variant: a timed-out accept is intentionally
/// indistinguishable from a peer close (no reply is spent on a possibly-spoofed
/// peer). See [`drive_open_loop`] for the shared terminal mapping.
///
/// `max_iters` / `tick_interval_ms` carry the same meaning as on
/// [`connect_and_open_session`] (test-determinism poll bound + SCE-scheduler
/// pump cadence; production passes `None` + [`DEFAULT_OPEN_TICK_MS`]).
pub async fn accept_and_open_session(
    accepted: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(accepted);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);

    // Accepting activation -> AwaitingInitSyn, whose onentry arms
    // `accepting.inactivity_timeout` (the open-deadline this path enforces).
    engine.process_event(E::InboundStart);

    drive_open_loop(
        inbound,
        actions,
        engine,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// Open a session to a locator discovered by scouting — the mode-agnostic
/// per-locator seam (R311ew).
///
/// Both scouting modes feed this the same way, which is the whole point of
/// the seam: active mode's `ScoutOutcome::Discovered(String)`
/// (wz-runtime-tokio::scouting_glue) and static mode's
/// [`synth_static_locators`] entries are both zenoh locator strings. This
/// parses one via [`wz_session_core::locator::parse_locator`] and hands the
/// typed endpoint to [`connect_and_open_session`] — "a discovered locator
/// opens the same way regardless of how scouting found it" (the contract the
/// `locator` module doc states from the parse side).
pub async fn open_session_at(
    locator: &str,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let parsed = parse_locator(locator).map_err(OpenError::BadLocator)?;
    connect_and_open_session(parsed, params, clock, max_iters, tick_interval_ms).await
}

/// Open a session to the first reachable peer in a static `deploy.connect[]`
/// list — the static scouting mode (docs/scouting-fsm.md §2.4.3, scouting
/// expressed as *absent*: no FSM, the locators come from config verbatim).
///
/// [`synth_static_locators`] normalises the configured locators in deploy
/// order; each is tried via [`open_session_at`] and the first that reaches
/// Established wins. Per-locator failures are logged (no silent skip) so the
/// diagnostic trail survives; the call returns [`OpenError::NoReachableLocator`]
/// only when every configured locator failed — the static-mode "configured
/// locators are wrong / unreachable" diagnostic (§2.4.3 reason #1).
///
/// MVP single-session: zenoh-pico opens the first peer then `_z_new_peer`s
/// the rest (session.c:157-189); the multi-peer mesh is Phase D+, so this
/// opens exactly one session to the first reachable peer.
pub async fn open_session_static(
    connect: &[String],
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let locators = synth_static_locators(connect);
    if locators.is_empty() {
        return Err(OpenError::NoReachableLocator);
    }
    for locator in &locators {
        match open_session_at(locator, params.clone(), clock, max_iters, tick_interval_ms).await {
            Ok(opened) => return Ok(opened),
            Err(e) => {
                log::warn!(
                    "wz session-open: static locator {locator:?} failed: {e:?}; trying next"
                );
            }
        }
    }
    Err(OpenError::NoReachableLocator)
}

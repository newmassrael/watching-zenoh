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
//! duplication). UDP session-open + the scouting -> parse -> dial -> open
//! wiring land in R311ew.

use std::io;
use std::sync::Arc;

use sce_rust_lua::LuaEngine;
use sce_rust_runtime::scripting::IScriptEngine;
use sce_rust_runtime::Engine;
use tokio::net::TcpStream;

use wz_session_core::locator::{ParsedLocator, Proto};

use crate::link_pipeline::{dial_tcp, wire_tcp_stream, TcpReadDriver};
use crate::runtime_impl::{TokioJoinHandle, TokioTime};
use crate::session_fsm_unicast::{SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy};
use crate::session_glue::{
    install_session_actions, poll_and_dispatch_one, DriverLoopOutcome, SessionInitParams,
    SessionLinkActions,
};
use crate::LostCause;

/// Dial a parsed locator to its raw transport — the mode-agnostic dial seam.
///
/// `Proto::Tcp` returns the connected [`TcpStream`] (split downstream by
/// [`connect_and_open_session`] via [`wire_tcp_stream`], per the R311et
/// raw-dial decision: the stream is dialed once and the split shape is
/// chosen by the consumer, not buried inside a unified driver).
///
/// `Proto::Udp` is not yet wired for session-open and surfaces a typed
/// `Unsupported` error rather than silently mis-dialing. Datagram
/// session-open lands in R311ew, where the return type generalises to a
/// transport union spanning both protocols.
pub async fn dial_locator(locator: ParsedLocator) -> io::Result<TcpStream> {
    match locator.proto {
        Proto::Tcp => dial_tcp(locator.addr).await,
        Proto::Udp => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "udp session-open dial not yet wired (R311ew); tcp only this round",
        )),
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
    pub inbound: TcpReadDriver,
    pub writer_handle: TokioJoinHandle<()>,
    pub clock: TokioTime,
}

/// Why a session did not reach Established.
#[derive(Debug)]
pub enum OpenError {
    /// Dial failed, or the locator protocol is not yet wired for
    /// session-open (UDP this round).
    Dial(io::Error),
    /// The link was lost mid-handshake (peer closed before OpenAck).
    LinkLost(LostCause),
    /// The FSM reached a terminal state before Established — e.g. a peer
    /// Close during the handshake.
    Terminal,
    /// The bounded iteration budget elapsed before Established (test guard;
    /// production passes `None`).
    IterationLimit,
}

/// Dial `locator`, split the connection into the R311et link pipeline, wire
/// the unicast session FSM in the Initiator role, and drive the inbound
/// handshake (peer InitAck -> OpenSyn -> peer OpenAck) until the FSM records
/// Established.
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
/// production passes `None`.
pub async fn connect_and_open_session(
    locator: ParsedLocator,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
) -> Result<OpenedSession, OpenError> {
    let stream = dial_locator(locator).await.map_err(OpenError::Dial)?;
    let (mut inbound, outbound, writer_handle) = wire_tcp_stream(stream);

    let actions = SessionLinkActions::new(outbound, params, clock);
    let script_engine: Arc<dyn IScriptEngine> = Arc::new(LuaEngine::new());
    install_session_actions(actions.clone(), &script_engine);
    let mut engine: Engine<SessionFsmUnicastPolicy> =
        Engine::new(SessionFsmUnicastPolicy::new(script_engine));
    engine.initialize();

    // Initiator activation -> SentInitSyn (send_init_syn enqueues InitSyn).
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);

    let mut iter: usize = 0;
    loop {
        if actions.trace_snapshot().record_established_at >= 1 {
            return Ok(OpenedSession {
                engine,
                actions,
                inbound,
                writer_handle,
                clock,
            });
        }
        if engine.is_in_final_state() {
            return Err(OpenError::Terminal);
        }
        if let Some(limit) = max_iters {
            if iter >= limit {
                return Err(OpenError::IterationLimit);
            }
            iter += 1;
        }
        if let DriverLoopOutcome::LinkLost(cause) =
            poll_and_dispatch_one(&mut inbound, &actions, &mut engine).await
        {
            return Err(OpenError::LinkLost(cause));
        }
    }
}

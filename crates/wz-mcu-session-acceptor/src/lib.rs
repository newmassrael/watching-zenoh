// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]
// Whole crate gated on `lwip_real_build` (set by build.rs from the lwip-sys
// `DEP_LWIP_LWIP_REAL_BUILD` metadata). Without it — a cross build with no
// `WZ_LWIP_PORT` — `wz::session_lwip` is empty, so `run_session` does not
// exist; the gate collapses the body to nothing rather than failing to
// resolve. Mirrors wz-link-lwip / wz-session-lwip.
#![cfg(lwip_real_build)]

//! wz-mcu-session-acceptor — Stage 5 MCU acceptor session e2e SSOT.
//!
//! [`run_acceptor_e2e`] drives the acceptor half of the zenoh unicast
//! handshake to `Established` and then dispatches one application Frame,
//! over a REAL lwIP loopback, through the Stage 4b
//! [`wz::session_lwip::run_session`] sync drive loop. The session
//! machinery is the shared [`wz_session_core`] SSOT; this crate is only
//! the e2e TOPOLOGY + verdict, factored into one `ClockSource`-generic
//! function so the host integration test and the QEMU bin
//! (`deploy/mcu-session-acceptor`) share a single implementation.
//!
//! ## The topology
//!
//! One process, two loopback UDP endpoints:
//!
//! - the ACCEPTOR — a [`wz::session_lwip::LwipUdpDriver`] over a session rx
//!   socket on [`SESSION_PORT`], driven by `run_session` in
//!   [`SessionRole::Acceptor`];
//! - a reactive crafted PEER — a plain [`wz::link_lwip::LwipUdpSocket`] on
//!   [`PEER_PORT`] that plays the initiator by hand.
//!
//! ## Why the peer is REACTIVE (not pre-queued)
//!
//! The peer opens with a crafted `InitSyn`, then drives the rest of the
//! handshake off the acceptor's REAL replies: it reads the acceptor's
//! `InitAck` off its own socket, decodes it with the production
//! [`parse_inbound`] SSOT, extracts the genuinely-minted anti-amplification
//! cookie, and echoes THAT cookie in its `OpenSyn`. So the
//! `cookie_valid()` admission guard (drive.rs §2.7) passes against a real
//! round-tripped cookie — not a value the test pre-computed and fed to both
//! sides. This is strictly more faithful than the AP
//! `session_fsm_accepting_path::r78` fixture (which pre-computes the cookie
//! it expects); the crafted-wire shape itself is borrowed verbatim from
//! that AP SSOT so the two profiles inspect the same handshake bytes.
//!
//! The reactive step lives in `run_session`'s per-iteration `on_event`
//! hook: after each acceptor dispatch the closure pumps the loopback netif,
//! delivers the acceptor's just-sent reply to the peer socket, and advances
//! the peer's small state machine ([`PeerPhase`]).

extern crate alloc;

use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::vec;
use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};

use wz::link_lwip::rx_sockets::bind_session_rx;
use wz::link_lwip::{ipv4_addr_loopback, LwipLink, LwipUdpSocket};
use wz::runtime_lwip::{LwipRuntime, LwipTime};
use wz::session_lwip::driver::SharedSessionSocket;
use wz::session_lwip::{run_session, LwipUdpDriver, SessionRole};
#[cfg(feature = "reassembly")]
use wz_session_wire_fixtures::craft_fragment_wire;
use wz_session_wire_fixtures::{craft_frame_wire, craft_initsyn_wire, craft_opensyn_wire};

// Re-export the trait a consumer must impl to supply monotonic time, so the
// host test and the QEMU bin depend only on THIS crate (single-dep facade
// boundary) rather than reaching into the wz facade themselves.
pub use wz::runtime_lwip::ClockSource;

use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::session_actions::SessionLinkActions;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;

/// UDP port the acceptor session socket binds to.
pub const SESSION_PORT: u16 = 7460;
/// UDP port the reactive crafted peer binds to.
pub const PEER_PORT: u16 = 7461;
/// Sequence number stamped on the post-handshake application Frame, used to
/// identify it in the dispatch stream (handshake frames are not `Frame`s).
const DATA_FRAME_SN: u64 = 7;
/// First fragment SN of the [`DataMode::FragmentChain`] reassembly chain.
#[cfg(feature = "reassembly")]
const FRAG_SN_0: u64 = 10;
/// Final fragment SN; the reassembled `FramePayload` is reported at this SN
/// (`report_outcome_reassembling` stamps the completion with the final
/// fragment's SN), so it is the data-dispatch sentinel in FragmentChain mode.
#[cfg(feature = "reassembly")]
const FRAG_SN_1: u64 = 11;
/// Milliseconds the [`OffsetClock`] jumps the [`DataMode::FragmentChainStalled`]
/// run forward, once the lone first fragment is INGESTED, to cross the chain's
/// `reassembly_timeout_ms` (500ms) deadline so the next sweep evicts it. Chosen
/// in the window `reassembly_timeout_ms (500) < STALL_JUMP_MS < lease (10_000)`
/// so the sweep fires but the Established lease deadline does NOT — isolating
/// the reassembly-timeout path. The handshake ran at offset 0 (frozen), safely
/// inside the 1_000ms `accepting_inactivity_ms` bound.
#[cfg(feature = "reassembly")]
const STALL_JUMP_MS: u32 = 2_000;
/// Iteration cap on the drive loop. The handshake + Frame complete in the
/// first ~3 iterations; the remainder spin the (no-op, with a frozen clock)
/// deadline branch. Bounds a regression so it fails fast instead of hanging.
const MAX_ITERS: usize = 64;

/// What the reactive peer sends after the handshake reaches `Established`, to
/// exercise the acceptor's data plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataMode {
    /// One whole `T_MID_FRAME` (the Stage 5 baseline data-plane proof).
    WholeFrame,
    /// A two-fragment `T_MID_FRAGMENT` chain the acceptor reassembles,
    /// re-parses, and dispatches as one `FramePayload`. Gated on the
    /// `reassembly` feature so this mode cannot be requested on a build that
    /// compiled the slot pool out — a build without reassembly literally
    /// has no `FragmentChain` variant to name (compile-time safety over a
    /// silent runtime no-op). The host reassembly test and the reassembly
    /// QEMU bin enable the feature.
    #[cfg(feature = "reassembly")]
    FragmentChain,
    /// A single FIRST fragment (`more=1`) of a chain whose continuation never
    /// arrives. The acceptor arms a reassembly slot; the harness then advances
    /// its [`OffsetClock`] past the chain's `reassembly_timeout_ms` deadline so
    /// the swept `run_session` loop evicts the chain (raising
    /// `ReassemblyTimeout`) — the timeout-eviction path the [`FragmentChain`]
    /// mode (which completes before any deadline) cannot exercise. Host-only:
    /// it needs the advancing clock, so the QEMU bin never requests it. Gated
    /// on `reassembly` like its sibling.
    ///
    /// [`FragmentChain`]: DataMode::FragmentChain
    #[cfg(feature = "reassembly")]
    FragmentChainStalled,
}

/// The verdict [`run_acceptor_e2e`] returns. The host test asserts
/// `EstablishedAndDispatched`; the QEMU bin maps it to a semihost exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptorE2eOutcome {
    /// The acceptor reached `Established` (cookie round-trip verified) AND
    /// the post-handshake application Frame was dispatched to the app layer.
    EstablishedAndDispatched,
    /// The acceptor never entered `Established` — the handshake stalled
    /// (admission denial, cookie mismatch, or a wire/decode fault).
    NotEstablished,
    /// `Established` was reached but the application Frame never surfaced as
    /// a `FramePayload` dispatch (data-plane fault).
    FrameNotDispatched,
    /// `Established` was reached and a reassembly chain was started, but its
    /// continuation never arrived; the deadline sweep evicted the chain
    /// (`ReassemblyTimeout`) instead of a dispatch completing. The expected
    /// verdict for [`DataMode::FragmentChainStalled`] — distinct from
    /// `FrameNotDispatched` (a fault) because the timeout is the correct
    /// outcome for an abandoned chain.
    ReassemblyTimedOut,
}

/// The full e2e result: the [`AcceptorE2eOutcome`] verdict plus per-stage
/// diagnostics. The host test asserts on `outcome` (and prints the rest on
/// failure); the QEMU bin maps `outcome` to a semihost exit code (and can
/// print the diagnostics so a stalled handshake is locatable on target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptorE2eReport {
    pub outcome: AcceptorE2eOutcome,
    /// Acceptor FSM advances dispatched (InitSyn + OpenSyn admitted = 2).
    pub advanced_fsm: u32,
    /// Inbound dispatches denied by an admission guard (cookie mismatch /
    /// half-open / rate) — surface as `SideEffectOnly`.
    pub side_effect: u32,
    /// Application `FramePayload` dispatches.
    pub frame_payload: u32,
    /// NetworkMessage count of the data-dispatch `FramePayload` (the one at
    /// the mode's expected SN). WholeFrame's empty payload decodes to 0; a
    /// reassembled FragmentChain to >= 1 — so the host reassembly test
    /// asserts the chain's bytes actually re-parsed into a message, not just
    /// that a `FramePayload` envelope surfaced.
    pub data_dispatch_msg_count: usize,
    /// Wire/codec parse errors surfaced during dispatch.
    pub parse_error: u32,
    /// Reassembly chains evicted by the deadline sweep
    /// (`IterationEvent::ReassemblyTimeout`). Non-zero only when a chain was
    /// started and abandoned — the `FragmentChainStalled` mode's success
    /// signal; 0 for `WholeFrame` / `FragmentChain` (which complete in time).
    pub reassembly_timed_out: u32,
    /// The peer read the acceptor's `InitAck` off its socket.
    pub peer_initack_seen: bool,
    /// Length of the cookie the peer extracted from that `InitAck` (0 = none).
    pub peer_cookie_len: usize,
    /// The peer echoed the cookie in an `OpenSyn`.
    pub peer_opensyn_sent: bool,
    /// The peer read the acceptor's `OpenAck` (acceptor is `Established`).
    pub peer_openack_seen: bool,
    /// The peer sent the post-handshake application Frame.
    pub peer_frame_sent: bool,
    /// Total datagrams the peer socket received (any kind / parse result).
    pub peer_rx_count: u32,
    /// Acceptor `send_init_ack_with_cookie` action fires (trace counter).
    pub init_ack_action_fired: u32,
    /// Acceptor `send_open_ack` action fires (trace counter).
    pub open_ack_action_fired: u32,
}

/// The reactive peer's handshake state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerPhase {
    /// Sent `InitSyn`; waiting for the acceptor's `InitAck` to read its
    /// minted cookie.
    AwaitInitAck,
    /// Echoed the cookie in `OpenSyn`; waiting for `OpenAck` (the acceptor is
    /// now `Established`) before sending the application Frame.
    AwaitOpenAck,
    /// Application Frame sent; nothing further for the peer to do.
    Done,
}

/// A [`ClockSource`] decorator that adds a harness-controlled millisecond
/// offset to the wrapped clock. The offset stays 0 for every mode except
/// [`DataMode::FragmentChainStalled`] (and on the QEMU SysTick), so the
/// frozen-clock determinism of the handshake + completion modes is
/// unchanged. For the stalled mode the `run_acceptor_e2e` `on_event` hook
/// bumps it (once, AFTER the lone fragment is ingested — the chain is armed
/// at the pre-bump `now_ms`) to [`STALL_JUMP_MS`], so the next loop
/// iteration's deadline sweep sees `now_ms` past the chain deadline and
/// evicts it. The offset is an `Arc<AtomicU32>` because [`ClockSource`] is
/// `Send + Sync`; the acceptor crate is already native-atomic-only (it pulls
/// `alloc::sync::Arc`), so the atomic adds no new target constraint.
#[derive(Clone)]
struct OffsetClock<C> {
    inner: C,
    offset_ms: Arc<AtomicU32>,
}

impl<C: ClockSource> ClockSource for OffsetClock<C> {
    fn now_us(&self) -> u64 {
        let offset_us = u64::from(self.offset_ms.load(Ordering::Relaxed)).saturating_mul(1000);
        self.inner.now_us().saturating_add(offset_us)
    }
}

/// Drive the acceptor session e2e to a verdict.
///
/// `clock_source` is the monotonic time the [`LwipRuntime`] and the lease
/// comparator read. The host test passes a frozen clock (no deadline ever
/// fires, so the run is fully deterministic); the QEMU bin passes its
/// SysTick clock (real ms, but the handshake completes in a few iterations,
/// far under any deadline).
///
/// `data_mode` selects what the reactive peer sends post-`Established`: a
/// whole [`DataMode::WholeFrame`] or a reassembled
/// [`DataMode::FragmentChain`]. Both verdicts assert the data dispatch
/// surfaced as a `FramePayload` (at [`DATA_FRAME_SN`] / [`FRAG_SN_1`]
/// respectively); FragmentChain additionally exercises the
/// `ReassemblyDispatcher` ingest + sweep and requires the `reassembly`
/// feature on the build.
pub fn run_acceptor_e2e<C: ClockSource>(clock_source: C, data_mode: DataMode) -> AcceptorE2eReport {
    let link = LwipLink::init();

    // ── The acceptor: a session rx socket wrapped in the MCU BoxedLinkDriver.
    //    The initial peer target is a placeholder the first inbound datagram
    //    overwrites via set_peer (the acceptor-reply path).
    let acceptor_sock: SharedSessionSocket = Rc::new(RefCell::new(
        bind_session_rx(&link, SESSION_PORT).expect("bind acceptor session rx"),
    ));
    let driver = Rc::new(LwipUdpDriver::new(
        acceptor_sock,
        ipv4_addr_loopback(),
        PEER_PORT,
    ));

    // ── The reactive crafted peer: a second real loopback endpoint.
    let mut peer_sock: LwipUdpSocket =
        LwipUdpSocket::bind(&link, PEER_PORT).expect("bind peer socket");

    // ── The session machinery (shared SSOT). The actions' clock MUST share
    //    an epoch with the loop clock (R263): build one LwipTime, clone it
    //    into the actions, pass the original to run_session.
    // The clock is wrapped in an `OffsetClock` whose offset stays 0 for every
    // mode except `FragmentChainStalled`, where the `on_event` hook below bumps
    // it to cross the reassembly deadline. Always-wrapping keeps one runtime
    // type across modes; offset 0 is a no-op (an atomic load).
    let offset_ms = Arc::new(AtomicU32::new(0));
    let runtime = LwipRuntime::new(OffsetClock {
        inner: clock_source,
        offset_ms: offset_ms.clone(),
    });
    let clock = LwipTime::new(&runtime);
    let driver_sink: Rc<dyn BoxedLinkDriver> = driver.clone();
    let actions = SessionLinkActions::new_generic(driver_sink, acceptor_params(), clock.clone());
    let timeouts = SessionTimeouts::spec_defaults();

    // Open the handshake: the initiator's first move. The reactive peer
    // drives OpenSyn + the application Frame off the acceptor's real replies
    // inside the on_event hook below.
    let _ = peer_sock.send_to(ipv4_addr_loopback(), SESSION_PORT, &craft_initsyn_wire());

    let mut peer_phase = PeerPhase::AwaitInitAck;
    let mut frame_dispatched = false;
    let mut advanced_fsm = 0u32;
    let mut side_effect = 0u32;
    let mut frame_payload = 0u32;
    let mut data_dispatch_msg_count = 0usize;
    let mut parse_error = 0u32;
    let mut reassembly_timed_out = 0u32;
    // The stalled mode bumps the clock exactly once, when the lone fragment is
    // ingested; this guards against a re-bump on any later Fragment outcome.
    #[cfg(feature = "reassembly")]
    let mut stall_armed = false;
    let mut peer_initack_seen = false;
    let mut peer_cookie_len = 0usize;
    let mut peer_opensyn_sent = false;
    let mut peer_openack_seen = false;
    let mut peer_frame_sent = false;
    let mut peer_rx_count = 0u32;

    // The SN the data dispatch surfaces at: the whole-frame SN, or — for a
    // reassembled chain — the final fragment's SN (the SN
    // `report_outcome_reassembling` stamps on the completion `FramePayload`).
    let expected_data_sn = match data_mode {
        DataMode::WholeFrame => DATA_FRAME_SN,
        #[cfg(feature = "reassembly")]
        DataMode::FragmentChain => FRAG_SN_1,
        // The stalled chain never completes, so no `FramePayload` ever matches
        // this SN; the value is inert (the verdict is the timeout count).
        #[cfg(feature = "reassembly")]
        DataMode::FragmentChainStalled => FRAG_SN_1,
    };

    run_session(
        &runtime,
        &link,
        &driver,
        &actions,
        &clock,
        &timeouts,
        SessionRole::Acceptor,
        Some(MAX_ITERS),
        |event| {
            match event {
                IterationEvent::Poll(outcome) => match outcome {
                    DriverLoopOutcome::AdvancedFsm => advanced_fsm += 1,
                    DriverLoopOutcome::SideEffectOnly => side_effect += 1,
                    DriverLoopOutcome::ParseError(_) => parse_error += 1,
                    DriverLoopOutcome::FramePayload { sn, messages, .. } => {
                        frame_payload += 1;
                        if *sn == expected_data_sn {
                            frame_dispatched = true;
                            data_dispatch_msg_count = messages.len();
                        }
                    }
                    // FragmentChainStalled: the instant the acceptor dispatches
                    // the lone first fragment, jump the clock past the chain's
                    // reassembly deadline. report_outcome_reassembling fires
                    // this Poll BEFORE it ingests + arms the chain (the arm uses
                    // the pre-bump now_ms), so the chain is armed at the current
                    // time and the NEXT iteration's sweep — at now_ms +
                    // STALL_JUMP_MS — evicts it.
                    #[cfg(feature = "reassembly")]
                    DriverLoopOutcome::Fragment { sn, more, .. }
                        if data_mode == DataMode::FragmentChainStalled
                            && *more
                            && *sn == FRAG_SN_0
                            && !stall_armed =>
                    {
                        offset_ms.store(STALL_JUMP_MS, Ordering::Relaxed);
                        stall_armed = true;
                    }
                    _ => {}
                },
                // The deadline sweep evicted an abandoned chain — count it (the
                // FragmentChainStalled verdict).
                IterationEvent::ReassemblyTimeout(n) => reassembly_timed_out += n as u32,
                _ => {}
            }

            // The reactive peer: deliver the acceptor's just-sent reply to
            // the peer socket and advance the peer SM. poll_loopback is
            // idempotent (run_session pumps it too); calling it here pulls
            // the reply the acceptor enqueued during THIS iteration's
            // dispatch so the peer can react without waiting a full tick.
            link.poll_loopback();
            while let Some(reply) = peer_sock.try_recv() {
                peer_rx_count += 1;
                match (peer_phase, parse_inbound(reply.data.as_slice())) {
                    // InitAck arrived — echo its minted cookie in OpenSyn.
                    (
                        PeerPhase::AwaitInitAck,
                        Ok(InboundFrame::Init {
                            is_ack: true, body, ..
                        }),
                    ) => {
                        peer_initack_seen = true;
                        if let Some(cookie) = body.cookie {
                            peer_cookie_len = cookie.len();
                            let _ = peer_sock.send_to(
                                ipv4_addr_loopback(),
                                SESSION_PORT,
                                &craft_opensyn_wire(&cookie),
                            );
                            peer_opensyn_sent = true;
                            peer_phase = PeerPhase::AwaitOpenAck;
                        }
                    }
                    // OpenAck arrived — the acceptor is Established; send the
                    // application data (whole Frame, or a fragment chain the
                    // acceptor reassembles).
                    (PeerPhase::AwaitOpenAck, Ok(InboundFrame::Open { is_ack: true, .. })) => {
                        peer_openack_seen = true;
                        match data_mode {
                            DataMode::WholeFrame => {
                                let _ = peer_sock.send_to(
                                    ipv4_addr_loopback(),
                                    SESSION_PORT,
                                    &craft_frame_wire(DATA_FRAME_SN, true),
                                );
                            }
                            #[cfg(feature = "reassembly")]
                            DataMode::FragmentChain => {
                                // A reliable two-fragment chain. The bodies
                                // [0x01]+[0x02] reassemble to [0x01,0x02],
                                // whose lead byte is an N_MID < 0x19 the
                                // acceptor's parse_frame_payload surfaces as a
                                // single NetworkMessage::Unknown — i.e. one
                                // FramePayload at the final fragment's SN. The
                                // session rx queue (depth 16) holds both
                                // datagrams; run_session drains one per tick.
                                let _ = peer_sock.send_to(
                                    ipv4_addr_loopback(),
                                    SESSION_PORT,
                                    &craft_fragment_wire(true, true, FRAG_SN_0, &[0x01]),
                                );
                                let _ = peer_sock.send_to(
                                    ipv4_addr_loopback(),
                                    SESSION_PORT,
                                    &craft_fragment_wire(true, false, FRAG_SN_1, &[0x02]),
                                );
                            }
                            #[cfg(feature = "reassembly")]
                            DataMode::FragmentChainStalled => {
                                // Only the FIRST fragment (more=1). The
                                // continuation (FRAG_SN_1) is never sent, so the
                                // acceptor's armed chain is left dangling and the
                                // deadline sweep evicts it once the OffsetClock
                                // crosses the reassembly window.
                                let _ = peer_sock.send_to(
                                    ipv4_addr_loopback(),
                                    SESSION_PORT,
                                    &craft_fragment_wire(true, true, FRAG_SN_0, &[0x01]),
                                );
                            }
                        }
                        peer_frame_sent = true;
                        peer_phase = PeerPhase::Done;
                    }
                    _ => {}
                }
            }
        },
    );

    let outcome = if !actions.is_established() {
        AcceptorE2eOutcome::NotEstablished
    } else if frame_dispatched {
        AcceptorE2eOutcome::EstablishedAndDispatched
    } else if reassembly_timed_out > 0 {
        // Established, no dispatch, but a chain was evicted on its deadline —
        // the abandoned-chain timeout path, not a fault.
        AcceptorE2eOutcome::ReassemblyTimedOut
    } else {
        AcceptorE2eOutcome::FrameNotDispatched
    };

    let trace = actions.trace_snapshot();

    AcceptorE2eReport {
        outcome,
        advanced_fsm,
        side_effect,
        frame_payload,
        data_dispatch_msg_count,
        parse_error,
        reassembly_timed_out,
        peer_initack_seen,
        peer_cookie_len,
        peer_opensyn_sent,
        peer_openack_seen,
        peer_frame_sent,
        peer_rx_count,
        init_ack_action_fired: trace.send_init_ack_with_cookie,
        open_ack_action_fired: trace.send_open_ack,
    }
}

/// Acceptor session params. The signing key (>= 32 bytes) backs the
/// HMAC-SHA256 cookie the acceptor mints on `InitAck` and verifies on
/// `OpenSyn`; the peer never needs it (it reads the minted cookie off the
/// wire). Mirrors `wz_session_lwip::session_drive` test params.
fn acceptor_params() -> SessionInitParams {
    SessionInitParams {
        version: 0x05,
        whatami: 0x02,
        zid: vec![0x0A, 0x0B, 0x0C, 0x0D],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease: 10,
        lease_in_seconds: true,
        initial_sn: 0,
        cookie: vec![0u8; 16],
        cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect(">=32-byte key"),
    }
}

// The synthetic handshake wires (craft_initsyn / craft_opensyn) + the
// application Frame (craft_frame) come from `wz_session_wire_fixtures`, the
// no_std SSOT shared with the wz-runtime-tokio session-FSM drive tests, so
// both profiles inspect byte-identical independent-oracle frames.

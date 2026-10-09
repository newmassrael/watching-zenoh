// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! wz-mcu-session-acceptor — Stage 5 MCU acceptor session e2e SSOT.
//!
//! [`run_acceptor_e2e_on`] drives the acceptor half of the zenoh unicast
//! handshake to `Established` and then dispatches one application Frame,
//! through the cooperative drive loop's [`SessionPump`] — the same sequence
//! `run_session` runs. The session machinery is the shared
//! [`wz_session_core`] SSOT; this crate is only the e2e TOPOLOGY + verdict,
//! factored into one `ClockSource`-generic function so the host integration
//! tests and the QEMU images share a single implementation.
//!
//! ## The topology
//!
//! Two loopback UDP endpoints on one network stack, which an
//! [`AcceptorTopology`] supplies:
//!
//! - the ACCEPTOR — the session's link on [`SESSION_PORT`], driven in
//!   `SessionRole::Acceptor`;
//! - a reactive crafted PEER — a plain socket on [`PEER_PORT`] that plays the
//!   initiator by hand.
//!
//! R2917 — the topology is a trait. It used to be lwIP's, written into the
//! function, so no profile whose network stack is not lwIP (Zephyr's own
//! sockets) could run this handshake. The lwIP topology is [`lwip`] (feature
//! `lwip`, on by default), and [`run_acceptor_e2e`] keeps its signature for
//! every existing caller.
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
//! sides. The crafted-wire shape itself is borrowed verbatim from the AP
//! `session_fsm_accepting_path::r78` fixture so the two profiles inspect the
//! same handshake bytes.
//!
//! The peer reacts after EVERY drive iteration, not only when the loop raises
//! an event, so the e2e does not depend on a stack delivering a reply within
//! the iteration that sent it. R2917 measured that this is not load-bearing
//! today: with the peer reacting on events only, the Zephyr-socket image still
//! established, because its loopback had the reply queued by then too. It is
//! kept because the dependence it removes is a property of the stack, not of
//! the session.

extern crate alloc;

use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;

use wz::runtime_coop::session_drive::{
    SessionDatagramLink, SessionDriveConfig, SessionPump, SessionRole,
};
use wz::runtime_coop::{CoopRuntime, CoopTime};
#[cfg(feature = "reassembly")]
use wz_session_wire_fixtures::craft_fragment_wire;
use wz_session_wire_fixtures::{craft_frame_wire, craft_initsyn_wire, craft_opensyn_wire};

// Re-export the trait a consumer must impl to supply monotonic time, so the
// host test and the QEMU bin depend only on THIS crate (single-dep facade
// boundary) rather than reaching into the wz facade themselves.
pub use wz::runtime_coop::ClockSource;
// Re-export the drop-reason enum so a host test can assert the SPECIFIC
// reason (e.g. OutOfOrder) carried on a `ReassemblyDropped` event, not just
// that some drop happened.
pub use wz_session_core::driver_loop::ReassemblyDropReason;

use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::WhatAmI;

#[cfg(all(feature = "lwip", lwip_real_build))]
pub mod lwip;
#[cfg(all(feature = "lwip", lwip_real_build))]
pub use lwip::{run_acceptor_e2e, run_acceptor_e2e_with_progress, LwipTopology};

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
/// Non-consecutive SN the [`DataMode::FragmentChainOoo`] peer sends as the
/// second fragment (the expected next after FRAG_SN_0=10 is 11; sending 12
/// skips 11), tripping the strict-in-order `fragment.ooo` abort.
#[cfg(feature = "reassembly")]
const FRAG_SN_OOO: u64 = 12;
/// Iteration cap on the drive loop. The handshake + Frame complete in the
/// first ~3 iterations; the remainder spin the (no-op, with a frozen clock)
/// deadline branch. Bounds a regression so it fails fast instead of hanging.
const MAX_ITERS: usize = 64;
/// R311y813 — the fixture's per-handshake cookie nonce. Fixed, like
/// `acceptor_params`' signing key: the peer echoes the cookie the acceptor
/// really minted, so this e2e is nonce-VALUE-agnostic and only needs a nonce to
/// be installed at all (the slot's default denies). A deploy draws it per
/// handshake from the §5.I intrinsics RNG.
const FIXTURE_COOKIE_NONCE: u64 = 0x5A5A_5A5A_5A5A_5A5A;

/// R311y819 — this e2e's
/// [`EntropySource`](wz_session_core::entropy::EntropySource), and the reason the fixed value
/// above is now a FIXTURE rather than a deploy pattern.
///
/// Before this round the constant was handed straight to
/// `refresh_cookie_nonce`, which meant the only MCU shape in the tree
/// DEMONSTRATED installing a constant — and a board copying the demo inherited
/// one cookie per zid for its whole service life. The constant now reaches the
/// slot through the same port a real board plugs its TRNG into
/// ([`new_session_actions`](wz::runtime_coop::session_runtime::new_session_actions)), so what a
/// deploy copies is the seam, and what it replaces is this type.
///
/// It deliberately does NOT satisfy the port's stated contract — the bytes are
/// predictable — which is what the name says out loud. It is admissible here
/// for the same reason `acceptor_params` fixes the signing key: this e2e
/// asserts that the peer's echo of the REAL minted cookie passes the guard,
/// a property that holds for any nonce value and needs a deterministic one to
/// be reproducible on a frozen-clock board.
///
/// R2913 — PUBLIC, and no longer chosen inside the e2e: the source is the
/// CALLER's, as it is on a real board, so a profile with an entropy seam of
/// its own (FreeRTOS's `FreertosEntropy`) runs this e2e through that seam, and
/// a caller that has none says so by passing this.
pub struct FixtureEntropy;

impl wz_session_core::entropy::EntropySource for FixtureEntropy {
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
        // Little-endian over the fixture constant, repeating — so a draw of 8
        // bytes reproduces FIXTURE_COOKIE_NONCE exactly through the trait's
        // fixed byte order, and the e2e's expectations are unchanged from the
        // pre-port shape.
        let src = FIXTURE_COOKIE_NONCE.to_le_bytes();
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = src[i % src.len()];
        }
        Ok(())
    }
}

/// The two endpoints of the e2e, on one network stack.
///
/// R2917. The acceptor's link has two faces, handed out separately because a
/// network stack may keep them as separate objects (lwIP's driver and its
/// input pump) or as one (a Zephyr socket link): the session's outbound sink,
/// and the drive loop's inbound [`SessionDatagramLink`]. The crafted peer is
/// a plain socket on the same stack.
pub trait AcceptorTopology {
    /// The acceptor's link as the drive loop reads it.
    type Link: SessionDatagramLink;

    /// The acceptor's outbound sink, which the session's action bundle keeps.
    fn acceptor_sink(&self) -> Rc<dyn BoxedLinkDriver>;

    /// The acceptor's inbound face, which the drive loop owns. It must share
    /// its socket with [`Self::acceptor_sink`].
    fn acceptor_link(&self) -> Self::Link;

    /// Send one datagram from the peer to the acceptor's [`SESSION_PORT`].
    fn peer_send(&mut self, bytes: &[u8]);

    /// The next datagram the peer has received, if any, after giving the
    /// stack the chance to deliver what the acceptor just sent.
    fn peer_try_recv(&mut self) -> Option<Vec<u8>>;
}

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
    /// the swept drive loop evicts the chain (raising `ReassemblyTimeout`) —
    /// the timeout-eviction path the [`FragmentChain`] mode (which completes
    /// before any deadline) cannot exercise. Host-only: it needs the advancing
    /// clock, so the QEMU bin never requests it. Gated on `reassembly` like
    /// its sibling.
    ///
    /// [`FragmentChain`]: DataMode::FragmentChain
    #[cfg(feature = "reassembly")]
    FragmentChainStalled,
    /// A two-fragment chain whose second fragment carries a NON-CONSECUTIVE SN
    /// (FRAG_SN_0=10 then FRAG_SN_OOO=12, skipping 11). The strict-in-order
    /// policy (§2.5) aborts the chain on ingest (`fragment.ooo`), which
    /// surfaces as `IterationEvent::ReassemblyDropped(OutOfOrder)` — the
    /// abort-path proof. No advancing clock needed (the abort is immediate on
    /// the second fragment), so a frozen clock suffices. Gated on `reassembly`.
    #[cfg(feature = "reassembly")]
    FragmentChainOoo,
}

/// The verdict [`run_acceptor_e2e_on`] returns. The host test asserts
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
    /// `Established` was reached and a reassembly chain was started, but a
    /// fragment ingest aborted/refused it (`IterationEvent::ReassemblyDropped`)
    /// instead of completing — e.g. the out-of-order abort. The expected
    /// verdict for [`DataMode::FragmentChainOoo`].
    ReassemblyDropped,
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
    /// Reassembly chains dropped at ingest (`IterationEvent::ReassemblyDropped`
    /// — out-of-order / capacity abort, or quota / pool refusal). Non-zero in
    /// the `FragmentChainOoo` mode (an OutOfOrder abort); 0 otherwise.
    pub reassembly_dropped: u32,
    /// The reason of the most recent reassembly drop (`None` if none). Lets a
    /// test assert the SPECIFIC reason (e.g. `OutOfOrder`) rather than only
    /// that a drop occurred.
    pub last_drop_reason: Option<ReassemblyDropReason>,
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

/// The stage a running acceptor e2e is WAITING in, announced once on entering
/// it through [`run_acceptor_e2e_on_with_progress`].
///
/// R3171 (open-debt item 815). The e2e is one call to a bare-metal image, and a
/// guest that stops making progress inside it (the SysTick-versus-spinlock
/// deadlock of item 815 was exactly that) used to leave the harness one line,
/// `... e2e starting`, and a 30 s timeout: no way to tell a handshake that never
/// got its `InitAck` from one that stalled after `OpenAck`. The image prints
/// [`AcceptorStage::name`] on each entry, so the LAST such line a hung boot
/// printed is the stage it is stalled in.
///
/// The stages are the reactive peer's waits, in handshake order. A stage that
/// is never entered (the run failed earlier) is not announced, which is the
/// information a reader wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcceptorStage {
    /// `InitSyn` sent; waiting for the acceptor's `InitAck` (and its cookie).
    AwaitInitAck,
    /// `OpenSyn` sent with the round-tripped cookie; waiting for `OpenAck`.
    AwaitOpenAck,
    /// The post-handshake data sent; waiting for the acceptor to dispatch it
    /// (or for the drive loop's iteration cap to end the run).
    AwaitDispatch,
}

impl AcceptorStage {
    /// A short stable token for the stage, for a console line.
    pub const fn name(self) -> &'static str {
        match self {
            AcceptorStage::AwaitInitAck => "await-initack",
            AcceptorStage::AwaitOpenAck => "await-openack",
            AcceptorStage::AwaitDispatch => "await-dispatch",
        }
    }
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

/// Drive the acceptor session e2e over `topology` to a verdict.
///
/// `clock_source` is the monotonic time the [`CoopRuntime`] and the lease
/// comparator read. The host test passes a frozen clock (no deadline ever
/// fires, so the run is fully deterministic); a QEMU image passes its board
/// clock (real ms, but the handshake completes in a few iterations, far under
/// any deadline).
///
/// `data_mode` selects what the reactive peer sends post-`Established`: a
/// whole [`DataMode::WholeFrame`] or a reassembled chain. Both verdicts
/// assert the data dispatch surfaced as a `FramePayload` (at
/// [`DATA_FRAME_SN`] / [`FRAG_SN_1`] respectively); a chain additionally
/// exercises the `ReassemblyDispatcher` ingest + sweep and requires the
/// `reassembly` feature on the build.
///
/// `on_fragment` fires once per DISPATCHED fragment (the `Fragment` Poll),
/// BEFORE the reassembly ingest arms/continues the chain (the arm reads the
/// pre-call `now_ms`). It is a neutral seam: the QEMU images and the
/// completion/ooo host tests pass a no-op; the `FragmentChainStalled` host
/// test passes a closure that advances its own controllable clock past the
/// chain deadline. Only fires under the `reassembly` feature
/// (`DriverLoopOutcome::Fragment` is gated).
///
/// `entropy` (R2913) is the profile's entropy source, installed through the
/// MCU construction seam: the per-handshake cookie nonce and the cookie
/// signing key are drawn from it. A board passes its own; a caller with no
/// source passes [`FixtureEntropy`] by name.
pub fn run_acceptor_e2e_on<T, C, E, H>(
    topology: T,
    clock_source: C,
    entropy: E,
    data_mode: DataMode,
    on_fragment: H,
) -> AcceptorE2eReport
where
    T: AcceptorTopology,
    C: ClockSource,
    E: wz_session_core::entropy::EntropySource + Send + 'static,
    H: FnMut(),
{
    run_acceptor_e2e_on_with_progress(
        topology,
        clock_source,
        entropy,
        data_mode,
        on_fragment,
        |_stage| {},
    )
}

/// [`run_acceptor_e2e_on`] that also announces each [`AcceptorStage`] through
/// `on_stage` as the e2e ENTERS it (R3171, open-debt item 815).
///
/// `on_stage` runs inside the drive loop, so it must be cheap and must not
/// block: a bare-metal image prints one console line, a host test pushes into
/// a vector. A caller that wants no announcements uses
/// [`run_acceptor_e2e_on`], which passes a no-op that compiles away.
///
/// The announcements are ordered and each fires at most once per run:
/// [`AcceptorStage::AwaitInitAck`] right after the opening `InitSyn`,
/// [`AcceptorStage::AwaitOpenAck`] when the cookie is read off the `InitAck`,
/// [`AcceptorStage::AwaitDispatch`] when the data is sent after `OpenAck`.
pub fn run_acceptor_e2e_on_with_progress<T, C, E, H, S>(
    mut topology: T,
    clock_source: C,
    entropy: E,
    data_mode: DataMode,
    mut on_fragment: H,
    mut on_stage: S,
) -> AcceptorE2eReport
where
    T: AcceptorTopology,
    C: ClockSource,
    E: wz_session_core::entropy::EntropySource + Send + 'static,
    H: FnMut(),
    S: FnMut(AcceptorStage),
{
    // The hook only fires under `reassembly` (the Fragment outcome is gated);
    // reference it so the non-reassembly build does not flag an unused param.
    #[cfg(not(feature = "reassembly"))]
    let _ = &mut on_fragment;

    // ── The session machinery (shared SSOT). The actions' clock MUST share
    //    an epoch with the loop clock (R263): build one CoopTime, clone it
    //    into the actions, hand the original to the pump.
    let runtime = CoopRuntime::new(clock_source);
    let clock = CoopTime::new(&runtime);
    // R311y819 — through the MCU CONSTRUCTION SEAM, which draws the cookie
    // nonce from the supplied `EntropySource`, the way the AP's
    // `new_session_actions` draws from `getrandom`.
    let mut entropy = entropy;
    let params = acceptor_params(&mut entropy);
    let actions = wz::runtime_coop::session_runtime::new_session_actions(
        topology.acceptor_sink(),
        params,
        clock.clone(),
        entropy,
    );

    // Open the handshake: the initiator's first move. The reactive peer
    // drives OpenSyn + the application data off the acceptor's real replies.
    topology.peer_send(&craft_initsyn_wire());
    on_stage(AcceptorStage::AwaitInitAck);

    let mut peer_phase = PeerPhase::AwaitInitAck;
    let mut frame_dispatched = false;
    let mut advanced_fsm = 0u32;
    let mut side_effect = 0u32;
    let mut frame_payload = 0u32;
    let mut data_dispatch_msg_count = 0usize;
    let mut parse_error = 0u32;
    let mut reassembly_timed_out = 0u32;
    let mut reassembly_dropped = 0u32;
    let mut last_drop_reason: Option<ReassemblyDropReason> = None;
    let mut peer_initack_seen = false;
    let mut peer_cookie_len = 0usize;
    let mut peer_opensyn_sent = false;
    let mut peer_openack_seen = false;
    let mut peer_frame_sent = false;
    let mut peer_rx_count = 0u32;

    // The SN the data dispatch surfaces at: the whole-frame SN, or — for a
    // reassembled chain — the final fragment's SN (the SN
    // `report_outcome_reassembling` stamps on the completion `FramePayload`).
    // The stalled and ooo chains never complete, so their value is inert.
    let expected_data_sn = match data_mode {
        DataMode::WholeFrame => DATA_FRAME_SN,
        #[cfg(feature = "reassembly")]
        DataMode::FragmentChain | DataMode::FragmentChainStalled | DataMode::FragmentChainOoo => {
            FRAG_SN_1
        }
    };

    // The same sequence `run_session` runs — one executor pass, then one
    // `step` — with the peer given its turn after every iteration.
    let mut pump = SessionPump::new(
        runtime.clone(),
        topology.acceptor_link(),
        actions.clone(),
        clock.clone(),
        SessionDriveConfig {
            timeouts: SessionTimeouts::spec_defaults(),
            role: SessionRole::Acceptor,
            max_iters: Some(MAX_ITERS),
        },
    );
    loop {
        pump.runtime().run_until_idle();
        let finished = pump.step(&mut |event: IterationEvent<'_>| match event {
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
                // A fragment was dispatched (before the ingest arms the
                // chain). Notify the caller's hook — the stalled host test
                // uses it to advance its clock past the chain deadline so
                // the next sweep evicts; every other caller passes a no-op.
                #[cfg(feature = "reassembly")]
                DriverLoopOutcome::Fragment { .. } => on_fragment(),
                _ => {}
            },
            // The deadline sweep evicted an abandoned chain — count it (the
            // FragmentChainStalled verdict).
            IterationEvent::ReassemblyTimeout(n) => reassembly_timed_out += n as u32,
            // A fragment ingest aborted/refused a chain — count it + record
            // the reason (the FragmentChainOoo verdict asserts OutOfOrder).
            IterationEvent::ReassemblyDropped(reason) => {
                reassembly_dropped += 1;
                last_drop_reason = Some(reason);
            }
            _ => {}
        });

        // The reactive peer: take whatever the acceptor has sent it and
        // advance the peer SM.
        while let Some(reply) = topology.peer_try_recv() {
            peer_rx_count += 1;
            match (peer_phase, parse_inbound(&reply)) {
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
                        topology.peer_send(&craft_opensyn_wire(&cookie));
                        peer_opensyn_sent = true;
                        peer_phase = PeerPhase::AwaitOpenAck;
                        on_stage(AcceptorStage::AwaitOpenAck);
                    }
                }
                // OpenAck arrived — the acceptor is Established; send the
                // application data (whole Frame, or a fragment chain the
                // acceptor reassembles).
                (PeerPhase::AwaitOpenAck, Ok(InboundFrame::Open { is_ack: true, .. })) => {
                    peer_openack_seen = true;
                    match data_mode {
                        DataMode::WholeFrame => {
                            topology.peer_send(&craft_frame_wire(DATA_FRAME_SN, true));
                        }
                        #[cfg(feature = "reassembly")]
                        DataMode::FragmentChain => {
                            // A reliable two-fragment chain. The bodies
                            // [0x01]+[0x02] reassemble to [0x01,0x02], whose
                            // lead byte is an N_MID < 0x19 the acceptor's
                            // parse_frame_payload surfaces as a single
                            // NetworkMessage::Unknown — i.e. one FramePayload
                            // at the final fragment's SN.
                            topology.peer_send(&craft_fragment_wire(
                                true,
                                true,
                                FRAG_SN_0,
                                &[0x01],
                            ));
                            topology.peer_send(&craft_fragment_wire(
                                true,
                                false,
                                FRAG_SN_1,
                                &[0x02],
                            ));
                        }
                        #[cfg(feature = "reassembly")]
                        DataMode::FragmentChainStalled => {
                            // Only the FIRST fragment (more=1). The
                            // continuation is never sent, so the acceptor's
                            // armed chain is left dangling and the deadline
                            // sweep evicts it once the caller's clock crosses
                            // the reassembly window.
                            topology.peer_send(&craft_fragment_wire(
                                true,
                                true,
                                FRAG_SN_0,
                                &[0x01],
                            ));
                        }
                        #[cfg(feature = "reassembly")]
                        DataMode::FragmentChainOoo => {
                            // First fragment (sn=10, more=1) arms the chain;
                            // the second carries a NON-CONSECUTIVE sn=12
                            // (skipping the expected 11), so strict in-order
                            // aborts the chain (fragment.ooo) on ingest.
                            topology.peer_send(&craft_fragment_wire(
                                true,
                                true,
                                FRAG_SN_0,
                                &[0x01],
                            ));
                            topology.peer_send(&craft_fragment_wire(
                                true,
                                true,
                                FRAG_SN_OOO,
                                &[0x02],
                            ));
                        }
                    }
                    peer_frame_sent = true;
                    peer_phase = PeerPhase::Done;
                    on_stage(AcceptorStage::AwaitDispatch);
                }
                _ => {}
            }
        }

        if finished.is_some() {
            break;
        }
    }

    let outcome = if !actions.is_established() {
        AcceptorE2eOutcome::NotEstablished
    } else if frame_dispatched {
        AcceptorE2eOutcome::EstablishedAndDispatched
    } else if reassembly_timed_out > 0 {
        // Established, no dispatch, but a chain was evicted on its deadline —
        // the abandoned-chain timeout path, not a fault.
        AcceptorE2eOutcome::ReassemblyTimedOut
    } else if reassembly_dropped > 0 {
        // Established, no dispatch, but a chain was aborted/refused at ingest
        // (e.g. out-of-order) — the malformed-stream drop path, not a fault.
        AcceptorE2eOutcome::ReassemblyDropped
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
        reassembly_dropped,
        last_drop_reason,
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
///
/// R2913 — the key is drawn from the caller's `entropy`, the same source the
/// cookie nonce comes from, so a board that supplies a source gets both
/// secrets from it. A source that cannot produce the key stops the e2e loudly:
/// a session with no signing key would admit nothing.
fn acceptor_params(
    entropy: &mut impl wz_session_core::entropy::EntropySource,
) -> SessionInitParams {
    SessionInitParams {
        version: 0x05,
        whatami: WhatAmI::Peer,
        zid: vec![0x0A, 0x0B, 0x0C, 0x0D],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: vec![0u8; 16],
        // R311y820 — through the SAME §2.5 port the cookie nonce uses, so this
        // fixture demonstrates the production shape rather than the literal a
        // board would otherwise copy.
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        cookie_signing_key: SigningKey::from_entropy(entropy)
            .expect("the entropy source produced no signing key"),
    }
}

// The synthetic handshake wires (craft_initsyn / craft_opensyn) + the
// application Frame (craft_frame) come from `wz_session_wire_fixtures`, the
// no_std SSOT shared with the wz-runtime-tokio session-FSM drive tests, so
// both profiles inspect byte-identical independent-oracle frames.

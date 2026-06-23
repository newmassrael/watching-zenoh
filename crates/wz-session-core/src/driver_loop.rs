// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R76 / R83 / R311di-12 — Driver-loop outcome envelope + iteration
//! event observer surface.
//!
//! `DriverLoopOutcome` summarises a single iteration of
//! `poll_and_dispatch_one` (wz-runtime-tokio): typed FSM advance,
//! KeepAlive side-effect, R74 `FramePayload` with the decoded
//! `NetworkMessage` batch, parse error, or link-lost event.
//!
//! `IterationEvent<'a>` wraps either a borrowed `&DriverLoopOutcome`
//! (the poll arm fired) or a `LeaseCheckOutcome` (the lease-deadline
//! arm fired), and is the observer callback's parameter inside
//! `drive_session_until_terminal`.
//!
//! Both types are runtime-agnostic — they only reference primitive
//! types, `Vec`, and earlier-migrated wz-session-core types
//! (`NetworkMessage`, `InboundParseError`, `LostCause`,
//! `LeaseCheckOutcome`) plus the wz-codecs `ExtEntry` projection from
//! `FramePayload.extensions`. Alloc-gated due to the Vec fields.

use alloc::vec::Vec;

use wz_codecs::ext_entry::ExtEntryOwned;

use crate::lease::{KeepAliveCheckOutcome, LeaseCheckOutcome};
use crate::link::LostCause;
use crate::network_message::NetworkMessage;
use crate::parse_error::InboundParseError;

/// R76 — outcome of a single iteration of the production driver
/// loop. Five observable outcomes the caller dispatches on: a typed
/// FSM event reached the engine; a KeepAlive parsed and updated the
/// lease stamp but did not advance the FSM (R72b); a Frame envelope
/// parsed and its payload decoded into a `NetworkMessage` batch the
/// application layer should dispatch (R74); the wire bytes failed to
/// parse (the helper raises `FramingError` to the FSM and returns
/// `ParseError` for logging); or the link itself terminated.
///
/// `#[derive(Debug)]` derives transitively over wz-codecs codec
/// structs (e.g. `ExtEntry`) — those carry the category-uniform
/// `Debug + Clone + PartialEq` derive set per
/// `sce-build::forge::rust_derive_policy::RustDeriveCategory::CodecStruct`
/// SSOT (SCE 14ff5e36d).
#[derive(Debug)]
pub enum DriverLoopOutcome {
    /// A typed `SessionFsmUnicastEvent` reached `Engine::process_event`;
    /// any state transition triggered by the event has completed.
    AdvancedFsm,
    /// The inbound frame parsed to a `KeepAlive` record. The lease
    /// stamp was updated inside `handle_inbound` (R72b); the engine
    /// state is unchanged.
    SideEffectOnly,
    /// R74 — the inbound frame parsed to a `Frame` transport envelope
    /// whose tail payload decoded into a batch of `NetworkMessage`
    /// records. The session FSM is unchanged (Frame receipt is not a
    /// session-state trigger); the application layer dispatches
    /// `messages` against its per-MID handler set.
    FramePayload {
        reliable: bool,
        sn: u64,
        messages: Vec<NetworkMessage>,
        has_ext: bool,
        extensions: Vec<ExtEntryOwned>,
    },
    /// `parse_inbound` rejected the wire bytes, OR the Frame envelope
    /// parsed but `parse_frame_payload` could not decode an authored
    /// network-MID envelope inside the payload batch (e.g. a truncated
    /// `Request` body). The helper has already injected `FramingError`
    /// into the engine so the session-fsm `framing.error` transition
    /// fires; the variant is returned so the caller can log the
    /// underlying error.
    ParseError(InboundParseError),
    /// The link reported `LostCause`. The helper has injected
    /// `LinkLost` into the engine so the `link.lost` transition
    /// fires; the cause is returned for logging.
    LinkLost(LostCause),
    /// R311ke — an inbound Frame/Fragment SN fell outside its channel's
    /// half-window ([`crate::sn::RxSn`] gate — zenoh-pico
    /// `_z_sn_precedes`, unicast/rx.c:100-185): a stale, duplicated, or
    /// reordered datagram. Dropped without FSM advance (pico's silent
    /// drop — an INFO-level event, not a session error); the payload
    /// never reaches the application layer. On a rejection the drive
    /// helper also clears the channel's in-progress reassembly chain
    /// (pico's dbuf-clear, rx.c:112-113) so a chain whose continuation
    /// was superseded never completes from mixed generations. TCP's
    /// in-order delivery cannot produce this; UDP unicast can.
    #[cfg(feature = "codec-frame")]
    RxSnRejected { reliable: bool, sn: u64 },
    /// R311kc — the InitAck's size parameters exceeded our InitSyn
    /// advertisement (the zenoh-pico
    /// `_Z_ERR_TRANSPORT_OPEN_SN_RESOLUTION` rejection,
    /// unicast/transport.c:123-140: "Any of the size parameters in the
    /// InitAck must be less or equal than the one in the InitSyn").
    /// The dispatcher has already injected `FramingError` so the FSM's
    /// `framing.error` arm tears the session down with
    /// `CloseReason::Invalid` (wire Close(INVALID) — pico aborts
    /// without a Close frame; wz spends the one frame on a clean
    /// teardown since the initiator-side reply is not an amplification
    /// vector). Surfaced as its own variant so the open loop maps it to
    /// a typed open error instead of folding it into `Terminal`.
    #[cfg(feature = "codec-init-body")]
    InitAckCapsRejected,
    /// R3b — a Z_EXT_AUTH method rejected the peer on a handshake recv stage
    /// (a bad usrpwd credential / unknown user / missing required sub-ext, or a
    /// malformed auth ext). The dispatcher has already injected `FramingError`
    /// so the FSM tears the session down with `CloseReason::Invalid` (wire
    /// Close(INVALID)) — the wz mirror of zenoh's establishment FSM
    /// `?`-propagating the usrpwd verify error into a transport close
    /// (`auth/usrpwd.rs:418/424`). Surfaced as its own variant so the open loop
    /// maps it to a typed open-loop auth-reject error (the
    /// `InitAckCapsRejected` pattern). The carried `AuthError` identifies the
    /// method failure for logging.
    #[cfg(feature = "session-extauth")]
    AuthRejected(crate::auth_dispatch::AuthError),
    /// R311im — the inbound frame parsed to a transport `Fragment`
    /// (`T_MID_FRAGMENT`, MID `0x06`). Reassembly is stateful — the slot
    /// pool ([`crate::reassembly_dispatch::ReassemblyDispatcher`]) lives in
    /// the drive loop, not in the pure `poll_and_dispatch_one` dispatch
    /// helper — so the helper surfaces the decoded fragment here and the
    /// drive loop feeds it to the dispatcher. On chain completion the drive
    /// loop synthesizes a `FramePayload` from the reassembled bytes (the
    /// reassembled message re-enters the same per-MID dispatch path a
    /// `T_MID_FRAME` payload would). The session FSM is unchanged (fragment
    /// receipt is not a session-state trigger, like `Frame`).
    #[cfg(feature = "reassembly")]
    Fragment {
        reliable: bool,
        sn: u64,
        more: bool,
        payload: Vec<u8>,
        has_ext: bool,
        extensions: Vec<ExtEntryOwned>,
    },
}

/// R83 — per-iteration event surfaced to the
/// `drive_session_until_terminal` observer callback. Each
/// iteration of the driver loop runs exactly one branch of the
/// inner `tokio::select!` (or the no-baseline `await`) and fires
/// the callback with the matching variant before looping.
///
/// Variant choice mirrors the loop body's two work paths:
///
/// - [`IterationEvent::Poll`] fires when the
///   `poll_and_dispatch_one` arm completes — i.e. the link
///   produced a `LinkEvent`. The borrowed [`DriverLoopOutcome`]
///   reflects whatever the dispatch helper returned: typed FSM
///   advance, `KeepAlive` side-effect, R74 `FramePayload` with
///   the decoded `NetworkMessage` batch, `ParseError`, or
///   `LinkLost`. Application-layer dispatch reads
///   `FramePayload.messages` here.
/// - [`IterationEvent::Lease`] fires when the lease-deadline
///   sleep arm wins the `tokio::select!` race — i.e. the peer
///   has gone silent. The carried [`LeaseCheckOutcome`] is the
///   helper's verdict (`NoBaseline` / `WithinLease` / `Expired`);
///   on `Expired` the FSM has already been advanced to `Closing`
///   inside the helper, so the next loop top will return
///   `Terminated`.
///
/// The borrow `'a` is the loop iteration's stack frame. Observers
/// that need to retain outcome data across iterations must clone
/// the relevant fields (e.g. `FramePayload.messages.clone()`) into
/// owned storage; the reference does not outlive the callback.
///
/// Synchronous contract. The callback runs inside the
/// `tokio::select!` arm, so heavy work blocks the loop. Callers
/// with expensive consumers should buffer (`Vec`, `mpsc::Sender`)
/// inside the closure and drain on a separate task.
///
/// `Copy` because both variants are payload-cheap: `Poll` carries
/// only a `&DriverLoopOutcome` reference (references are `Copy`),
/// and `Lease(LeaseCheckOutcome)` is itself a unit-only enum that
/// derives `Copy`. Making `IterationEvent` `Copy` lets a single
/// observer callback fan the same event out to multiple
/// `dispatch_iteration_event` consumers (subscriber + queryable
/// registries) without having to manually re-construct the variant
/// or split the dispatch into separate iterations.
#[derive(Clone, Copy, Debug)]
pub enum IterationEvent<'a> {
    /// `poll_and_dispatch_one` returned. The borrowed outcome
    /// covers all five `DriverLoopOutcome` variants.
    Poll(&'a DriverLoopOutcome),
    /// `tokio::time::sleep` won the select race against the poll
    /// future; `check_lease_deadline` has already run and its
    /// verdict is carried here. `Copy` because the enum has only
    /// unit variants.
    Lease(LeaseCheckOutcome),
    /// R311kx — the keepalive TX deadline check ran (the AP loop runs it
    /// on every deadline-arm wake alongside the lease check; the MCU loop
    /// when the busy-poll compare crosses the TX deadline) and its
    /// verdict is carried here. On `Emitted` a KeepAlive wire frame went
    /// out through `send_keep_alive` — the TX liveness counterpart of
    /// `Lease` (which watches the PEER's silence). Carries the ungated
    /// [`KeepAliveCheckOutcome`] so this variant — and every consumer's
    /// match — stays feature-independent; only the producer
    /// (`check_keepalive_deadline`) is `transport-keepalive`-gated.
    /// `Copy` (a unit-only enum).
    KeepAlive(KeepAliveCheckOutcome),
    /// The per-iteration reassembly deadline sweep evicted one or more
    /// chains whose continuation never arrived (the carried `usize` is the
    /// count). Emitted by [`crate::drive::sweep_reporting`] from both the AP
    /// and MCU drive loops so the application layer can observe a peer that
    /// began a fragmented message and abandoned it — the silent-eviction
    /// counterpart of the `Poll(FramePayload)` chain-completion event.
    /// `Copy` (a bare `usize`). Consumers that only care about `Poll` ignore
    /// it via their `if let Poll(..)` partial match.
    ReassemblyTimeout(usize),
    /// A reassembly chain was dropped at ingest — an out-of-order /
    /// capacity-overflow abort, or a per-peer-quota / pool-exhaustion
    /// refusal. Emitted by [`crate::drive::report_outcome_reassembling`] when
    /// a fragment ingest returns a terminal non-completion outcome, so the
    /// application can observe a malformed / abusive fragment stream — the
    /// drop counterpart of `Poll(FramePayload)` (completion) and
    /// `ReassemblyTimeout` (deadline). Carries an ungated
    /// [`ReassemblyDropReason`] (a stable observer-API mirror of the
    /// reassembly-internal abort/refuse reasons) so this variant — and every
    /// consumer's match — stays feature-independent.
    ReassemblyDropped(ReassemblyDropReason),
}

/// Build the [`DriverLoopOutcome`] a completed reassembly chain re-enters
/// the loop with: the reassembled bytes go back through
/// [`parse_frame_payload`](crate::network_message::parse_frame_payload), so
/// the application's per-MID dispatch sees the reassembled message exactly
/// as it sees a `T_MID_FRAME` payload. The reassembled bytes are the inner
/// NetworkMessage batch; transport ext chains were per-fragment, so the
/// reassembled outcome carries none. Shared by the unicast
/// [`crate::drive::report_outcome_reassembling`] and the multicast
/// [`crate::multicast_dispatch::ingest_multicast_fragment`] completion
/// closures (one re-entry SSOT). `reassembly` implies `codec-frame`, so
/// the payload parser is in scope.
#[cfg(feature = "reassembly")]
pub fn reassembled_frame_outcome(reliable: bool, sn: u64, msg: &[u8]) -> DriverLoopOutcome {
    match crate::network_message::parse_frame_payload(msg) {
        Ok(messages) => DriverLoopOutcome::FramePayload {
            reliable,
            sn,
            messages,
            has_ext: false,
            extensions: Vec::new(),
        },
        Err(codec_err) => DriverLoopOutcome::ParseError(InboundParseError::Codec(codec_err)),
    }
}

/// Why a reassembly chain was dropped at ingest, surfaced on
/// [`IterationEvent::ReassemblyDropped`]. A stable, feature-independent
/// mirror of the reassembly-internal `AbortReason` / `RefuseReason` (which
/// live behind the `reassembly` feature); kept separate so the public
/// observer API does not leak the gated dispatcher types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReassemblyDropReason {
    /// A continuation arrived whose SN was not the chain's expected next SN —
    /// strict in-order policy aborted the chain (§2.5, `fragment.ooo`).
    OutOfOrder,
    /// Staging the fragment would exceed the slot's capacity — the §7.1
    /// reassembly-capacity hard error.
    CapacityOverflow,
    /// The peer already held `per_peer_quota` open chains (§5.M quota-first).
    PeerQuota,
    /// Every slot was occupied by another peer's in-progress chain.
    PoolExhausted,
}

#[cfg(feature = "reassembly")]
impl ReassemblyDropReason {
    /// Map a terminal non-completion ingest to this feature-independent
    /// observer mirror; `None` for the progressing outcomes (Begun /
    /// Continued / Reassembled), which the caller reports through their
    /// own events. Shared by the unicast and multicast ingest reporters
    /// (one mapping SSOT). Lives here, not on `IngestOutcome`: the
    /// reassembly dispatcher also compiles on the no-alloc MCU profile,
    /// where this alloc-gated observer module does not exist.
    pub fn from_ingest(
        outcome: crate::reassembly_dispatch::IngestOutcome,
    ) -> Option<ReassemblyDropReason> {
        use crate::reassembly_dispatch::{AbortReason, IngestOutcome, RefuseReason};
        match outcome {
            IngestOutcome::Aborted(AbortReason::OutOfOrder) => {
                Some(ReassemblyDropReason::OutOfOrder)
            }
            IngestOutcome::Aborted(AbortReason::CapacityOverflow) => {
                Some(ReassemblyDropReason::CapacityOverflow)
            }
            IngestOutcome::Refused(RefuseReason::PeerQuota) => {
                Some(ReassemblyDropReason::PeerQuota)
            }
            IngestOutcome::Refused(RefuseReason::PoolExhausted) => {
                Some(ReassemblyDropReason::PoolExhausted)
            }
            IngestOutcome::Begun | IngestOutcome::Continued | IngestOutcome::Reassembled => None,
        }
    }
}

/// R76b — terminal result of a production session drive loop. Runtime-
/// agnostic: the AP `drive_session_until_terminal` (tokio `select!` loop)
/// and the lwIP MCU `run_session` (sync polling loop) both return this.
/// Stage 4b hoisted it here from `wz-runtime-tokio::session_glue` so the
/// two loops share one outcome SSOT; wz-runtime-tokio re-exports it.
#[derive(Debug, PartialEq, Eq)]
pub enum DriverOutcome {
    /// The engine reached a terminal state
    /// (`Engine::is_in_final_state() == true`) via FSM transition.
    /// Production callers exit the session lifecycle here; the
    /// outbound driver close has already been dispatched by the
    /// `Closed.onentry` action chain.
    Terminated,
    /// The caller-supplied `max_iters` cap was reached without the
    /// engine reaching a terminal state. Test callers use this to
    /// bound runaway loops; production callers pass `None` for
    /// unlimited iteration.
    IterationLimit,
}

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

use crate::lease::LeaseCheckOutcome;
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
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Typed reject surface for the outbound payload / keyexpr-carrying
//! wire-emit actions that are NOT the DECLARE family —
//! [`SessionLinkActions::send_push_literal`] / `_aliased` /
//! `send_push_del_*` / `send_push_with_meta_*` (publish),
//! `send_request_query` / `_with_meta` (query), and
//! `send_interest_liveliness_subscriber` (interest).
//!
//! These three families share exactly one failure model — a build
//! that elides the codec (`FeatureDisabled`) or caller data that
//! overflows the declared bounded-codec capacity (`Codec`) — so they
//! share one error type rather than three identical ones. The DECLARE
//! family keeps its own richer [`crate::send_declare_error::SendDeclareError`]
//! because it additionally pre-checks the outbound mapping table and
//! keyexpr pico-safety (failure modes these actions do not have).
//!
//! Distinct from `SendDeclareError` (ISP): a publish/query/interest
//! caller never observes `Keyexpr` / `ReservedMappingIdZero` /
//! `UnknownMappingId` / `MissingKeyexpr`, so those variants are not in
//! scope here.

use core::fmt;

use sce_forge_runtime::codec::CodecError;

/// W3 (SCE pin 7a94d084a) — typed reject from an outbound
/// payload/keyexpr-carrying wire-emit action. Every variant is a
/// no-emit reject (no wire bytes leave on `Err`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendWireError {
    /// The caller data (payload / keyexpr suffix) exceeded the
    /// declared bounded-codec capacity while copying into the
    /// no-alloc owned mirror — the same bound the decode path
    /// enforces. The wrapped [`CodecError`] is the codec-level cause.
    Codec(CodecError),
    /// R311g1 signature-stability — the matching `codec-*` /
    /// `declare-*` Cargo feature is OFF in this build, so the wire
    /// emit path is elided. The `SessionLinkActions` method signature
    /// stays stable regardless of feature configuration (per
    /// `feedback_signature_stability`); the caller observes the
    /// build-time choice as an honest runtime reject rather than a
    /// missing symbol or a falsely-`Ok` no-op.
    ///
    /// Variant ordering: appended at end so existing match arms in
    /// downstream crates surface a non-exhaustive-match warning rather
    /// than silently rebind a prior variant.
    FeatureDisabled,
    /// F2 — the session's transport is not currently accepting data
    /// sends: the supervisor tore it down for re-dial
    /// (`reset_for_reopen`) or the session FSM released the link
    /// (`release_link`), and Established has not (re-)entered. Mirrors
    /// zenoh-pico's `_Z_ERR_TRANSPORT_NOT_AVAILABLE` — pico's tx path
    /// fails on the dead transport's mutex/NULL where wz's writer-channel
    /// enqueue would otherwise swallow the bytes silently. A no-emit
    /// reject; the caller retries after the session re-establishes.
    TransportUnavailable,
    /// B5b-2b (R311nc) / R311nf — a non-`Push`
    /// [`NetworkMessage`](crate::network_message::NetworkMessage)
    /// reached the MULTICAST send arm of the
    /// `Session::send_network_message` seam. A multicast session
    /// originates only `Push` (its reply plane is drive-loop-sink-emitted,
    /// not routed through the seam); any other variant is an honest reject.
    ///
    /// R311nf narrowed the original two-condition definition: the prior
    /// first condition — "a unicast-only operation invoked on a multicast
    /// session, returning via `Session::actions()`" — is now a compile
    /// error rather than a runtime reject. `Session<_,_,Unicast>::actions()`
    /// is infallible; `Session<_,_,Multicast>` has no `actions()` method at
    /// all. This variant's sole remaining runtime meaning is the multicast
    /// non-Push message-variant mismatch described above.
    ///
    /// Deliberately DISTINCT from `FeatureDisabled` (a build-time codec
    /// elision — the matching Cargo feature may well be ON here) and from
    /// `TransportUnavailable` (a unicast link mid-reconnect). The R311na
    /// review #3b deferral ratified the distinction: a transport-variant
    /// mismatch must not be conflated with a feature-off no-op.
    ///
    /// Variant ordering: appended at end so existing match arms in
    /// downstream crates surface a non-exhaustive-match warning rather
    /// than silently rebind a prior variant.
    UnsupportedVariant,
    /// The message is larger than the profile's own reassembly cap, so its
    /// fragment chain could never be rejoined by a peer running this
    /// profile — the send is refused instead of emitted.
    ///
    /// Why refuse rather than emit and hope: fragmentation splits a message
    /// the link cannot carry whole, and the receiver stages the chunks until
    /// the chain completes. That staging is bounded (the reassembly slot
    /// `CAP`). A chain over the cap is dropped mid-stage, and the sender
    /// learns nothing — which is precisely the failure R311y484 recorded at
    /// the C ABI: `z_put` returned success for bytes that went nowhere, so a
    /// caller could not distinguish a delivered put from a discarded one.
    ///
    /// The bound is LOCAL and that is the whole of its claim. A peer's cap
    /// is not observable, so this does not promise delivery — a smaller-cap
    /// peer (zenoh-pico's `Z_FRAG_MAX_SIZE` is 4096 by default) may still
    /// drop a chain this side accepted. What it removes is the case the
    /// sender could have known about and reported: a message its OWN profile
    /// could not have reassembled. No wire bytes are emitted.
    ///
    /// Inert unless the host sets a cap
    /// ([`SessionLinkActions::set_max_reassembly_bytes`](crate::session_actions::SessionLinkActions::set_max_reassembly_bytes));
    /// the default is "no cap", so a profile that never configures one
    /// behaves exactly as before.
    ///
    /// Variant ordering: appended at end so existing match arms in
    /// downstream crates surface a non-exhaustive-match warning rather
    /// than silently rebind a prior variant.
    ExceedsReassemblyCap,
    /// R2238 (open-debt item 580) — the session's finite fragment TX budget
    /// ran out while a `T_MID_FRAGMENT` chain was being emitted, so the
    /// message was ABANDONED. Distinct from [`Self::ExceedsReassemblyCap`],
    /// which refuses a chain BEFORE any byte leaves and is a property of the
    /// message; this one is a property of the moment, and the same message
    /// sent again with credit available goes out whole.
    ///
    /// Two wire outcomes hide behind this one variant, and the difference is
    /// visible to the PEER rather than to the caller:
    ///
    ///   * the budget was already empty when the chain started — nothing was
    ///     emitted, and no marker is sent, because there is no chain for a
    ///     receiver to be holding. Upstream's equivalent arm restores the SN
    ///     and writes nothing (`common/pipeline.rs`, the `ext_first.is_some()`
    ///     branch);
    ///   * it ran out MID-CHAIN — the fragments already emitted are on the
    ///     wire, and a `0x3 Drop` stop fragment
    ///     ([`build_fragment_drop_wire`](crate::frame_encode::build_fragment_drop_wire))
    ///     follows them so the receiver releases its defragmentation buffer
    ///     instead of holding a chain that will never complete.
    ///
    /// Inert unless the host sets a budget
    /// ([`SessionLinkActions::set_fragment_tx_budget`](crate::session_actions::SessionLinkActions::set_fragment_tx_budget));
    /// the default is "unbounded", so a profile that never configures one
    /// behaves exactly as before.
    ///
    /// Variant ordering: appended at end so existing match arms in
    /// downstream crates surface a non-exhaustive-match warning rather
    /// than silently rebind a prior variant.
    FragmentTxBudgetExhausted,
}

impl fmt::Display for SendWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(e) => write!(
                f,
                "send_wire: caller data exceeded bounded-codec capacity \
                 while building owned mirror: {e:?}"
            ),
            Self::FeatureDisabled => f.write_str(
                "send_wire: matching codec-* Cargo feature is OFF in this \
                 build; wire emit elided (signature-stability contract — \
                 caller observes build-time choice as runtime reject)",
            ),
            Self::TransportUnavailable => f.write_str(
                "send_wire: transport not available (link released or \
                 reconnecting; Established not re-entered) — no bytes \
                 emitted; retry after the session re-establishes",
            ),
            Self::ExceedsReassemblyCap => f.write_str(
                "send_wire: message exceeds this profile's reassembly cap — \
                 its fragment chain could not be rejoined by a peer running \
                 this profile, so no bytes were emitted (refused locally \
                 rather than dropped silently mid-stage)",
            ),
            Self::UnsupportedVariant => f.write_str(
                "send_wire: non-Push NetworkMessage reached the multicast \
                 send arm — a multicast session originates only Push (the \
                 reply-plane variants are emitted by the drive-loop \
                 MulticastReplySink, never routed here) — no bytes emitted; \
                 a feature-off build returns FeatureDisabled instead",
            ),
            Self::FragmentTxBudgetExhausted => f.write_str(
                "send_wire: the session's fragment TX budget ran out while \
                 emitting this chain, so the message was abandoned — any \
                 fragments already on the wire are followed by a 0x3 Drop \
                 stop fragment so the peer releases its defragmentation \
                 buffer; retry once the budget is refilled",
            ),
        }
    }
}

impl core::error::Error for SendWireError {}

impl From<CodecError> for SendWireError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

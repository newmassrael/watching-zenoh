// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311nf (Level B, B5b-4) — the per-session transport TYPESTATE.
//!
//! [`Session`](super::Session) owns exactly one transport, the way
//! zenoh-pico's `_z_session_t` owns one `_z_transport_t`. pico models that
//! as a manually-tagged C union (`union { _unicast; _multicast; _raweth; }`
//! plus a separate `_z_transport_type_t _type` tag —
//! `vendor/zenoh-pico/include/zenoh-pico/transport/transport.h:224`), a C
//! limitation that admits the desync illegal-state of a tag disagreeing with
//! the union payload AND keeps every transport operation callable on every
//! session (the union has no per-tag method visibility).
//!
//! ## Why a typestate, not a runtime sum
//!
//! R311mm (B1) modelled this as a runtime sum `SessionTransport<R, T>` — a
//! Rust enum fusing tag and payload, a strict improvement on pico's manual
//! union. But a runtime sum models a fact that is *statically known at every
//! construction site*: a `Session` is built unicast (`Session::new`) or
//! multicast (`Session::new_multicast`) and never switches. Encoding that
//! known-at-construction fact at runtime forced a cascade of fallible
//! projections (R311nc `actions() -> Result`, R311nd `send_network_message`
//! runtime `match`, R311ne `is_established().unwrap_or(false)`) and left the
//! unicast drive entry point `dispatch_iteration_event{,_with}` *callable on a
//! multicast session*, where it silently no-ops the reply flush — an
//! illegal-state-REPRESENTABLE the session review flagged.
//!
//! R311nf lifts transport into a TYPE parameter `Session<R, T, Tp>` (the
//! typestate pattern). The transport-specific surface lives on
//! transport-specific `impl` blocks — `dispatch_iteration_event` only on
//! `Session<R, T, Unicast>`, `dispatch_multicast_iteration_event` only on
//! `Session<R, T, Multicast>` — so calling the unicast drive on a multicast
//! session is a COMPILE ERROR, not a silent runtime no-op
//! (unrepresentable-by-construction). [`TransportState`] carries each
//! transport's stored [`TransportState::Payload`] and its
//! [`TransportState::send_network_message`] dispatch (the `_z_send_n_msg`
//! analogue), so the transport-agnostic [`Session::publish`] seam stays a
//! single SSOT while the per-transport send body lives in one place each.
//!
//! The variant set is the closed, protocol-defined transport catalog
//! (unicast / multicast / — later — raweth); a third party cannot add a
//! transport without changing the wire spec, so [`TransportState`] is a
//! SEALED trait (`sealed::Sealed` supertrait), not an open extension point.
//! Each marker + its `TransportState` impl is `#[cfg]`-gated on its catalog
//! atom, so a single-transport build has exactly one inhabited marker and a
//! both-transport build has two; in every build the type system picks the
//! send body by monomorphization — no `match`, no `_ =>` escape arm, no
//! fallible transport-mismatch projection on the unicast surface.

#[cfg(feature = "transport-unicast")]
use std::sync::Arc;

#[cfg(all(feature = "transport-multicast", feature = "codec-push"))]
use wz_session_core::multicast_tx::MulticastTxItem;

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::send_wire_error::SendWireError;

#[cfg(feature = "transport-unicast")]
use crate::session_glue::SessionLinkActions;

mod sealed {
    /// Seal for [`super::TransportState`]: the transport catalog is closed
    /// (protocol-defined), so only the in-crate markers may implement it.
    pub trait Sealed {}
}

/// The transport a [`Session`](super::Session) owns, lifted to a TYPE
/// parameter (typestate). Each implementor is a zero-sized marker
/// ([`Unicast`] / [`Multicast`]); the associated [`Self::Payload`] is the
/// transport-specific handle the `Session` stores, and
/// [`Self::send_network_message`] is the per-transport send dispatch the
/// transport-agnostic [`Session::publish`](super::Session::publish) seam
/// fans through. Sealed — see the module docs for why the transport set is
/// closed, not an open extension point.
///
/// Generic over the same `(R, T)` as the owning `Session` so the unicast
/// payload's runtime + clock parameters stay in lockstep with the session
/// (the R311cw single-epoch invariant); the multicast payload uses neither,
/// but the trait stays parameterized so the unicast projection can name them.
pub trait TransportState<R: SessionRuntime, T: TimeSource>: sealed::Sealed {
    /// The transport-specific handle a `Session<R, T, Self>` stores in its
    /// `transport` field — the unicast action bundle, or the multicast TX
    /// seam. Replaces the old `SessionTransport` enum payload.
    type Payload;

    /// Send a fully-built [`NetworkMessage`](wz_session_core::network_message::NetworkMessage)
    /// over this transport — the wz analogue of zenoh-pico's `_z_send_n_msg`
    /// (`switch (zt->_type)` over the transport tag), but resolved at
    /// compile time by the typestate rather than at runtime. The unicast
    /// impl routes to the [`SessionLinkActions`] dispatch family (+ express
    /// batch flush); the multicast impl enqueues a [`MulticastTxItem`] onto
    /// the drive-loop channel.
    ///
    /// A build whose transport has no wire codec (no caller can construct a
    /// `NetworkMessage` to send) keeps an honest `Err(UnsupportedVariant)`
    /// body — the method is required so the agnostic
    /// [`Session::send_network_message`](super::Session::send_network_message)
    /// forwarder can name it uniformly, but it is never reached there.
    fn send_network_message(
        payload: &Self::Payload,
        msg: wz_session_core::network_message::NetworkMessage,
        reliable: bool,
        express: bool,
    ) -> Result<(), SendWireError>;
}

/// Typestate marker for a UNICAST session: the payload is the per-peer
/// handshake-driven [`SessionLinkActions`] bundle. Gated `transport-unicast`
/// because its payload names `SessionLinkActions`, which lives behind
/// wz-session-core's `session-unicast` gate (absent in a multicast-only build).
#[cfg(feature = "transport-unicast")]
pub struct Unicast;

/// Typestate marker for a MULTICAST session: the payload is the handshake-free
/// multicast TX seam (a `codec-push`-gated channel sender, or a bare RX-only
/// marker). Gated `transport-multicast`.
#[cfg(feature = "transport-multicast")]
pub struct Multicast;

#[cfg(feature = "transport-unicast")]
impl sealed::Sealed for Unicast {}
#[cfg(feature = "transport-multicast")]
impl sealed::Sealed for Multicast {}

#[cfg(feature = "transport-unicast")]
impl<R: SessionRuntime, T: TimeSource> TransportState<R, T> for Unicast {
    type Payload = Arc<SessionLinkActions<R, T>>;

    fn send_network_message(
        payload: &Self::Payload,
        msg: wz_session_core::network_message::NetworkMessage,
        reliable: bool,
        express: bool,
    ) -> Result<(), SendWireError> {
        // The unicast send capability (`SessionLinkActions::send_network_message`)
        // exists only with a wire codec (push / request / declare / interest);
        // a handshake-only unicast build has no `NetworkMessage` to originate,
        // so the method stays required (uniform with the multicast impl) but
        // returns an honest no-emit reject that no caller reaches.
        #[cfg(any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-declare",
            feature = "declare-interest"
        ))]
        {
            payload.send_network_message(msg, reliable, express)
        }
        #[cfg(not(any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-declare",
            feature = "declare-interest"
        )))]
        {
            let _ = (payload, msg, reliable, express);
            Err(SendWireError::UnsupportedVariant)
        }
    }
}

/// R311nf — the multicast transport payload (was the `SessionTransport::Multicast`
/// variant body). Carries the sender half of the channel
/// [`drive_multicast_session`](crate::multicast_glue::drive_multicast_session)
/// drains; `codec-push`-gated (the Put item builder + the item type need a TX
/// body codec) — a bare multicast build (JOIN/frame/close only, no data plane)
/// keeps the empty marker, an RX-only / beacon-node session. No `PhantomData`
/// over `(R, T)` is needed (unlike the old enum variant): the typestate's
/// `Session<R, T, Multicast>` binds `R`/`T` through its other fields
/// (`observer` / `fires` / `clock`), so the payload itself need not.
#[cfg(feature = "transport-multicast")]
#[derive(Clone)]
pub struct MulticastPayload {
    /// The sender half of the channel
    /// [`drive_multicast_session`](crate::multicast_glue::drive_multicast_session)
    /// drains; [`Session::publish`](super::Session::publish) enqueues a
    /// `MulticastTxItem` here. Absent in a non-`codec-push` build (RX-only).
    #[cfg(feature = "codec-push")]
    pub(crate) tx: tokio::sync::mpsc::UnboundedSender<MulticastTxItem>,
}

#[cfg(feature = "transport-multicast")]
impl<R: SessionRuntime, T: TimeSource> TransportState<R, T> for Multicast {
    type Payload = MulticastPayload;

    fn send_network_message(
        payload: &Self::Payload,
        msg: wz_session_core::network_message::NetworkMessage,
        reliable: bool,
        _express: bool,
    ) -> Result<(), SendWireError> {
        // UDP multicast is best-effort with no per-session batch window, so
        // `express` is ignored (parity with the old multicast send arm).
        #[cfg(feature = "codec-push")]
        {
            use wz_session_core::network_message::NetworkMessage;
            match msg {
                // A multicast Session originates only Push; any other variant
                // is an honest transport-variant mismatch (the reply-plane
                // variants Response / ResponseFinal / Oam are emitted by the
                // drive-loop MulticastReplySink, never routed here).
                NetworkMessage::Push(push) => {
                    let _ = payload.tx.send(MulticastTxItem::Push { push, reliable });
                    Ok(())
                }
                _ => Err(SendWireError::UnsupportedVariant),
            }
        }
        // No `codec-push`: the payload has no `tx` and there is no
        // `MulticastTxItem` to build, so a multicast Session cannot originate
        // any wire message. Honest reject.
        #[cfg(not(feature = "codec-push"))]
        {
            let _ = (payload, msg, reliable);
            Err(SendWireError::UnsupportedVariant)
        }
    }
}

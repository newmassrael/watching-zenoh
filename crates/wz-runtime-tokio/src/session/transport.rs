// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311mm (Level B, step B1) — the per-session transport sum.
//!
//! [`Session`](super::Session) owns exactly one transport, the way
//! zenoh-pico's `_z_session_t` owns one `_z_transport_t`. pico models that
//! as a manually-tagged C union (`union { _unicast; _multicast; _raweth; }`
//! plus a separate `_z_transport_type_t _type` tag —
//! `vendor/zenoh-pico/include/zenoh-pico/transport/transport.h:224`), which
//! admits the desync illegal-state of a tag that disagrees with the union
//! payload (a C limitation, no sum types).
//!
//! [`SessionTransport`] is the Rust sum that fuses the tag and the payload
//! into one inseparable value: "this session is unicast XOR multicast" is
//! made unrepresentable-otherwise, a strict improvement on pico's manual
//! union while staying faithful to its intent. The variant set is the
//! closed, protocol-defined transport catalog (unicast / multicast /
//! — later — raweth); it is NOT an open extension point (a third party
//! cannot add a transport without changing the wire spec), so a sum type is
//! the correct modeling, not a trait object. Each variant is `#[cfg]`-gated
//! on its catalog atom, so a single-transport build composes a degenerate
//! single-variant sum (the catalog composition made type-visible); a
//! both-transport build composes the full two-variant sum and the send-path
//! `match` runtime-dispatches over it — in every build the `match` stays
//! exhaustive with no `_ =>` escape arm.
//!
//! B1 inhabited only [`SessionTransport::Unicast`]. R311mn (B2) added the
//! [`SessionTransport::Multicast`] variant, initially gated
//! `all(transport-multicast, not(transport-unicast))` so it existed only in a
//! multicast-ONLY build. R311nd (B5b-2b tail) drops the `not(transport-unicast)`
//! qualifier — the variant is now plain `transport-multicast`-gated, so a
//! both-transport build can HOLD a multicast `Session` (the Level B
//! unification of multicast under the `Session` handle). The sum is therefore
//! single-variant in a single-transport build (Unicast in unicast-only,
//! Multicast in multicast-only) and TWO-variant in a both-transport build,
//! where [`Session::send_network_message`](super::Session::send_network_message)
//! runtime-dispatches and [`Session::actions`](super::Session::actions)
//! honestly rejects the multicast arm with `SendWireError::UnsupportedVariant`.

#[cfg(feature = "transport-multicast")]
use core::marker::PhantomData;
#[cfg(feature = "transport-unicast")]
use std::sync::Arc;

#[cfg(all(feature = "transport-multicast", feature = "codec-push"))]
use wz_session_core::multicast_tx::MulticastTxItem;

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;

#[cfg(feature = "transport-unicast")]
use crate::session_glue::SessionLinkActions;

/// The transport a [`Session`](super::Session) owns — the Rust analogue of
/// zenoh-pico's `_z_transport_t` tagged union (see the module docs for why
/// a sum type, not a trait).
///
/// Generic over the same `(R, T)` as the owning `Session` so the unicast
/// action bundle's runtime + clock parameters stay in lockstep with the
/// session (the R311cw single-epoch invariant).
pub(crate) enum SessionTransport<R: SessionRuntime, T: TimeSource> {
    /// A unicast session: the outbound [`SessionLinkActions`] bundle (the
    /// handshake-driven per-peer action machinery). Shared `Arc` so a
    /// `Session::clone` is cheap and several publish surfaces can bind the
    /// same physical session. Gated on `transport-unicast` because the
    /// payload names `SessionLinkActions`, which lives behind wz-session-core's
    /// `session-unicast` gate (absent in a multicast-only build).
    #[cfg(feature = "transport-unicast")]
    Unicast(Arc<SessionLinkActions<R, T>>),

    /// A multicast session (R311mn, B2): the handshake-free multicast
    /// transport. B2 inhabits this as a marker — a multicast `Session` owns
    /// the shared observer + clock + deferred-fire queue but carries no
    /// transport payload yet (`PhantomData` ties the otherwise-unused `R`/`T`
    /// to the enum, since the unicast variant that uses them is `cfg`'d out
    /// in this configuration). B3 promotes it to carry the multicast TX seam
    /// (`UnboundedSender<MulticastTxItem>`) when `Session::publish` learns to
    /// enqueue onto the multicast drive loop.
    ///
    /// Gated `all(transport-multicast, not(transport-unicast))`: a multicast
    /// `Session` is representable only in a multicast-ONLY build for now. In a
    /// both-transports build (preset-ap-router / -ap-full / -zenoh-cpp) a
    /// `Session` is always unicast and multicast still rides the standalone
    /// [`drive_multicast_session`](crate::multicast_glue::drive_multicast_session)
    /// loop; unifying both under one `Session` in a both-build is the Level B
    /// B5 round, which drops this `not(...)` gate and makes the send path
    /// runtime-transport-aware. The gate keeps the unicast
    /// [`Session::actions`](super::Session::actions) accessor's `match`
    /// exhaustive in every build (no panic arm, no `Option` churn) until B5.
    ///
    /// R311mo (B3) promotes the payload from a unit marker to carry the
    /// multicast TX seam: `tx` is the sender half of the channel
    /// [`drive_multicast_session`](crate::multicast_glue::drive_multicast_session)
    /// drains. [`Session::publish`](super::Session::publish) enqueues a
    /// `MulticastTxItem` here; the loop frames + multicasts it. `tx` is
    /// `codec-push`-gated (the Put item builder + the item type need a TX
    /// body codec) — a bare multicast build (JOIN/frame/close only, no data
    /// plane) keeps just `_marker`, an RX-only / beacon-node session.
    /// `_marker` ties the otherwise-unused `R`/`T` to the enum (in a
    /// multicast-only build the unicast variant that uses them is `cfg`'d
    /// out, and the TX channel is not generic over `R`/`T`; in a both-build
    /// the `Unicast` arm already binds `R`/`T`, so the marker is redundant
    /// but harmless).
    ///
    /// R311nd (B5b-2b tail) — gate widened from
    /// `all(transport-multicast, not(transport-unicast))` to plain
    /// `transport-multicast`: a both-transport build can now HOLD a multicast
    /// `Session` (the Level B unification), so the variant is representable
    /// alongside `Unicast`. The send path
    /// [`Session::send_network_message`](super::Session::send_network_message)
    /// runtime-dispatches over the two arms, and
    /// [`Session::actions`](super::Session::actions) honestly rejects with
    /// `SendWireError::UnsupportedVariant` on this arm.
    #[cfg(feature = "transport-multicast")]
    Multicast {
        #[cfg(feature = "codec-push")]
        tx: tokio::sync::mpsc::UnboundedSender<MulticastTxItem>,
        _marker: PhantomData<fn() -> (R, T)>,
    },
}

// Manual `Clone` — mirrors the owning `Session`'s manual impl. A derived
// `Clone` would add spurious `R: Clone + T: Clone` bounds; the unicast payload
// is `Arc<_>` (`Clone` for any inner type) and the multicast marker is
// `PhantomData` (`Copy`), so the bounds are unnecessary and would leak into
// every `Session::clone` call site. Each arm is `cfg`-gated to match its
// variant, so the `match` is exhaustive in every (single-variant) build.
impl<R: SessionRuntime, T: TimeSource> Clone for SessionTransport<R, T> {
    fn clone(&self) -> Self {
        match self {
            #[cfg(feature = "transport-unicast")]
            SessionTransport::Unicast(actions) => SessionTransport::Unicast(actions.clone()),
            #[cfg(feature = "transport-multicast")]
            SessionTransport::Multicast {
                #[cfg(feature = "codec-push")]
                tx,
                ..
            } => SessionTransport::Multicast {
                #[cfg(feature = "codec-push")]
                tx: tx.clone(),
                _marker: PhantomData,
            },
        }
    }
}

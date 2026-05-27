// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Link-layer types shared between LinkDriver impls and dispatch code.
//!
//! Carries the small wire-shape value types (TxFrame / RxFrame / LinkEvent
//! / LostCause) so MCU runtime profiles can express the same LinkDriver
//! contract without dragging in std / tokio. The LinkDriver trait itself
//! and its concrete TcpDriver / UdpDriver impls stay in wz-runtime-tokio
//! because those are tokio-specific (TcpStream / UdpSocket).
//!
//! Layer: §5.C link-tier value-type surface.

use alloc::vec::Vec;

/// Outbound payload to send over a link. The R51 baseline carries
/// raw bytes; future rounds extend to typed frames (carrying codec
/// metadata for re-encoding on the link side without copy).
pub struct TxFrame<'a> {
    pub bytes: &'a [u8],
}

/// Inbound frame received from a link. R51 baseline: owned `Vec<u8>`.
/// Future rounds (per docs/runtime-crate-tokio.md §2.3) will switch
/// this to a pool-slot borrow `RxFrame<'pool>` for zero-copy decode.
#[derive(Debug)]
pub struct RxFrame {
    pub bytes: Vec<u8>,
}

/// Single event source surfaced by a link driver. R51 baseline
/// emits only Ready / Rx / Lost; backpressure + framing_error +
/// tx_drained land when their consumers (codec-level decoder +
/// session FSM) are wired.
#[derive(Debug)]
pub enum LinkEvent {
    Ready,
    Rx(RxFrame),
    Lost { cause: LostCause },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LostCause {
    PeerClosed,
    Timeout,
    OsError,
}

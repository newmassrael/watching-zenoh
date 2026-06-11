// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311lv — the shared multicast RX classify + dispatch SSOT.
//!
//! The §3.1 RxDispatch decision — "which [`MulticastDispatcher`] method does an
//! inbound datagram's transport MID drive?" — lives here ONCE, consumed by BOTH
//! the AP drive loop (`wz_runtime_tokio::multicast_glue::drive_multicast_session`)
//! and the MCU drive loop (`wz_session_lwip::multicast_drive::run_multicast_session`).
//! Before R311lv each loop carried its own copy of the classify match; this
//! realises the engine-free contract those loops state — every decision
//! PRIMITIVE is the shared `wz_session_core` SSOT, the loops own only the IO +
//! clock structure around it.
//!
//! The JOIN admit, the Frame admit-and-fan, and the KeepAlive lease refresh are
//! handled here in full (none touch reassembly state). The reassembly-divergent
//! tails — Fragment reassembly, the out-of-order-Frame chain abort, and the
//! pre-Close peer-chain abort — are returned as [`MulticastRxNext`] for the
//! caller to layer with its own (feature-gated, profile-specific) reassembly
//! Router, a type the runtime-agnostic SSOT does not own.

use core::net::SocketAddr;

use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
use crate::inbound::{parse_inbound, InboundFrame};
use crate::multicast_dispatch::{FrameIngest, MulticastDispatcher};
use crate::multicast_join::{decode_join, validate_join};
use crate::multicast_params::MulticastParams;
use crate::network_message::parse_frame_payload;
use crate::wire_const;

/// What an inbound multicast datagram still needs from the caller AFTER the
/// shared [`dispatch_multicast_inbound`] has applied the non-reassembly
/// dispatch. `Done` for JOIN / KeepAlive / admitted-Frame / unknown MIDs; the
/// other variants hand the reassembly-divergent tail back to the loop (which
/// owns the reassembly Router).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastRxNext {
    /// Fully handled by the SSOT; nothing more for the caller.
    Done,
    /// The Frame was SN-gate-rejected as out-of-order. A caller with a
    /// reassembly Router should clear that peer-channel's in-progress chain
    /// (the dropped frame may have superseded its continuation). `reliable`
    /// selects the channel.
    FrameOutOfOrder { reliable: bool },
    /// A `T_MID_CLOSE`: the caller calls `close_by_src` (a reassembly caller
    /// aborts the peer's chains FIRST, before the slot index can recycle).
    Close,
    /// A `T_MID_FRAGMENT`: the caller reassembles it (or drops it when its
    /// reassembly feature is off — pico "Fragment dropped because
    /// fragmentation feature is deactivated").
    Fragment,
}

/// Classify one inbound multicast datagram by its transport MID and apply the
/// §3.2 dispatch that needs no reassembly state: JOIN -> validate + admit (own
/// zid filtered, since multicast loopback echoes our own beacon); Frame -> the
/// per-channel SN gate + (on Admit) fan the NetworkMessage batch to `on_event`
/// as an [`IterationEvent::Poll`]; KeepAlive -> lease refresh. Close and
/// Fragment are returned via [`MulticastRxNext`] for the caller's
/// reassembly-aware tail. `src` is the §3.2 peer key (the datagram source
/// address — Frame / KeepAlive / Close carry no zid on the wire, exactly like
/// zenoh-pico `_z_find_peer_entry`).
pub fn dispatch_multicast_inbound<F, const MAX_PEERS: usize>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    params: &MulticastParams,
    bytes: &[u8],
    src: SocketAddr,
    now_ms: u64,
    on_event: &mut F,
) -> MulticastRxNext
where
    F: FnMut(IterationEvent<'_>),
{
    match bytes.first().map(|h| h & 0x1f) {
        Some(wire_const::T_MID_JOIN) => {
            // A JOIN announces its zid; validate (§3.2 rejection rules), then
            // admit / refresh the peer at this address. Filter our own zid: a
            // node is not its own peer.
            if let Some(join) = decode_join(bytes) {
                if join.zid != params.zid.as_slice() {
                    if let Some(baseline) = validate_join(&join, params) {
                        dispatcher.ingest_join(join.zid, src, baseline, now_ms);
                    }
                }
            }
            MulticastRxNext::Done
        }
        Some(wire_const::T_MID_FRAME) => {
            // A1b data plane: decode, admit against the sender's per-channel SN
            // gate (which also refreshes its lease), and fan the NetworkMessage
            // batch to the observer. A frame from an unknown peer or a
            // malformed envelope / payload is dropped; an out-of-order SN hands
            // the in-progress-chain abort back to the caller.
            if let Ok(InboundFrame::Frame {
                reliable,
                sn,
                payload,
                has_ext,
                extensions,
            }) = parse_inbound(bytes)
            {
                match dispatcher.ingest_frame_by_src(src, reliable, sn, now_ms) {
                    FrameIngest::Admitted => {
                        if let Ok(messages) = parse_frame_payload(&payload) {
                            let outcome = DriverLoopOutcome::FramePayload {
                                reliable,
                                sn,
                                messages,
                                has_ext,
                                extensions,
                            };
                            on_event(IterationEvent::Poll(&outcome));
                        }
                        MulticastRxNext::Done
                    }
                    FrameIngest::OutOfOrder => MulticastRxNext::FrameOutOfOrder { reliable },
                    _ => MulticastRxNext::Done,
                }
            } else {
                MulticastRxNext::Done
            }
        }
        Some(wire_const::T_MID_FRAGMENT) => MulticastRxNext::Fragment,
        Some(wire_const::T_MID_KEEP_ALIVE) => {
            // A liveness ping refreshes the sender's lease (robustness if its
            // JOIN beacons are lost).
            dispatcher.refresh_by_src(src, now_ms);
            MulticastRxNext::Done
        }
        Some(wire_const::T_MID_CLOSE) => MulticastRxNext::Close,
        _ => MulticastRxNext::Done,
    }
}

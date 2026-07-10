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
//! pre-Close peer-chain abort — are returned as [`MulticastRxNext`].
//!
//! Two entry points layer that: [`dispatch_multicast_inbound`] is the classify
//! that returns the tail (a non-reassembly loop calls it and acts only on
//! `Close`); [`dispatch_multicast_inbound_reassembling`] (R311mh) is the
//! reassembly-aware wrapper that applies the FULL tail with the caller's
//! reassembly Router, so a reassembly-built loop calls ONE function and the tail
//! wiring is no longer hand-mirrored per loop. The Router type itself
//! (`ReassemblyDispatcher`) stays caller-owned (feature-gated, profile-specific
//! pool dims) — the SSOT takes it by `&mut`.

use core::net::SocketAddr;

use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
use crate::inbound::{parse_inbound, InboundFrame};
use crate::multicast_dispatch::{FrameIngest, MulticastDispatcher};
#[cfg(feature = "transport-qos")]
use crate::multicast_join::decode_join_qos;
use crate::multicast_join::{decode_join, validate_join};
use crate::multicast_params::MulticastParams;
use crate::network_message::parse_frame_payload;
use crate::wire_const;
// R311mh — the reassembly-divergent tail SSOT (dispatch_multicast_inbound_reassembling
// below): the Fragment / FrameOutOfOrder / Close handlers a reassembly-capable
// loop layers onto the classify. Gated like ingest_multicast_fragment.
#[cfg(all(feature = "reassembly", feature = "alloc"))]
use crate::multicast_dispatch::{
    abort_peer_chains, ingest_multicast_fragment_qos, multicast_chain_key,
};
#[cfg(all(feature = "reassembly", feature = "alloc"))]
use crate::reassembly_dispatch::ReassemblyDispatcher;

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
                        // R311y227 — group-agreed QoS admission (zenoh
                        // multicast/rx.rs `handle_join_from_unknown`): a non-qos
                        // node REFUSES a qos peer's JOIN (its per-priority frames
                        // would decode as "Unknown priority" against a single
                        // conduit), while a qos node ACCEPTS a non-qos peer and
                        // seeds its single DEFAULT conduit. `decode_join_qos` parses
                        // the JOIN `ext_qos` (`None` = a non-qos peer), and the
                        // per-priority next-SNs seed each of the peer's conduits.
                        #[cfg(feature = "transport-qos")]
                        {
                            let qos_next_sns = decode_join_qos(bytes);
                            if !(qos_next_sns.is_some() && !params.is_qos) {
                                dispatcher.ingest_join_qos(
                                    join.zid,
                                    src,
                                    baseline,
                                    qos_next_sns,
                                    now_ms,
                                );
                            }
                        }
                        #[cfg(not(feature = "transport-qos"))]
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
                priority,
                ..
            }) = parse_inbound(bytes)
            {
                // R311y227 — admit against the frame's OWN per-priority conduit
                // (the qos peer's per-conduit SN streams gate independently). A
                // non-qos frame decodes as `Priority::DEFAULT`, so it rides the
                // single DEFAULT conduit — byte-identical to the pre-R311y227 gate.
                match dispatcher.ingest_frame_by_src_qos(src, priority, reliable, sn, now_ms) {
                    FrameIngest::Admitted => {
                        if let Ok(messages) = parse_frame_payload(&payload) {
                            // The `ingest_frame_by_src` `&mut dispatcher` borrow
                            // ended at the match scrutinee (`FrameIngest` is a
                            // fieldless enum), so the dispatcher is free to
                            // re-borrow here for the §5.21 routing-namespace
                            // ingress strip.
                            #[cfg_attr(not(feature = "routing-namespace"), allow(unused_mut))]
                            let mut outcome = DriverLoopOutcome::FramePayload {
                                reliable,
                                sn,
                                messages,
                                has_ext,
                                extensions,
                                // R311y227 — the frame's decoded `ext_qos` band,
                                // now that the per-priority conduit gate
                                // (`ingest_frame_by_src_qos`) isolates each priority
                                // stream. Surfaced to the delivery outcome so a
                                // router egress / app observes the same band the
                                // frame carried. DEFAULT for a non-qos frame (no
                                // ext_qos), so a non-`transport-qos` build is
                                // unchanged.
                                priority,
                            };
                            // §5.21 routing-namespace — strip this peer's inbound
                            // batch (per-peer via `src`) BEFORE the observer fan,
                            // the multicast INGRESS seam (the `ENamespace` mirror).
                            // No-op when no namespace is installed / feature off.
                            // §5.21 router-multicast-faces (I3a) — resolve this
                            // peer's aliased Push keyexprs against the DeclKexpr
                            // declarations it sent over the group, per peer via
                            // `src`, BEFORE the fan (the id-only -> literal mirror
                            // of the namespace strip). Runs BEFORE the namespace
                            // strip so a namespaced+aliased push is first made
                            // literal, then the prefix is stripped from the
                            // literal. No-op when the feature is off (MCU) or the
                            // peer declared no aliases.
                            #[cfg(feature = "multicast-declarations")]
                            dispatcher.apply_declared_aliases(src, &mut outcome);
                            // §5.21 router-multicast-faces (sub plane, S1) — ingest
                            // this peer's DeclareSubscriber / UndeclareSubscriber into
                            // its per-peer remote-sub table (read-only on the batch),
                            // AFTER the alias pass (so an aliased sub resolves against
                            // the peer's now-populated keyexpr_table) and BEFORE the
                            // namespace strip (the alias table is namespace-inclusive).
                            // No-op when the feature is off (MCU) or the peer sent no
                            // sub declaration.
                            #[cfg(feature = "multicast-declarations")]
                            dispatcher.apply_declared_subscriptions(src, &outcome);
                            #[cfg(feature = "routing-namespace")]
                            dispatcher.apply_namespace_ingress(src, &mut outcome);
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

/// The reassembly-aware RX dispatch: [`dispatch_multicast_inbound`] PLUS the
/// reassembly-divergent tail, applied with the caller's reassembly Router so
/// the out-of-order-Frame chain abort, Fragment reassembly, and pre-Close
/// peer-chain abort live HERE ONCE instead of being hand-mirrored in each
/// drive loop's match (R311mh — the session-review Finding B: the classify was
/// already SSOT via [`dispatch_multicast_inbound`], but the tail wiring was
/// duplicated byte-for-byte between the AP `multicast_glue` and MCU
/// `multicast_drive` loops). Both reassembly-built loops call THIS; a
/// non-reassembly loop calls the plain [`dispatch_multicast_inbound`] and acts
/// only on [`MulticastRxNext::Close`] (FrameOutOfOrder / Fragment are no-ops
/// without a Router). zenoh-pico parity: the Close tail aborts the peer's
/// chains BEFORE `close_by_src`, so a recycled slot index can never continue a
/// dead peer's chain.
#[cfg(all(feature = "reassembly", feature = "alloc"))]
pub fn dispatch_multicast_inbound_reassembling<
    F,
    const MAX_PEERS: usize,
    const SLOTS: usize,
    const CAP: usize,
>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP>,
    params: &MulticastParams,
    bytes: &[u8],
    src: SocketAddr,
    now_ms: u64,
    on_event: &mut F,
) where
    F: FnMut(IterationEvent<'_>),
{
    match dispatch_multicast_inbound(dispatcher, params, bytes, src, now_ms, on_event) {
        MulticastRxNext::Done => {}
        MulticastRxNext::FrameOutOfOrder { reliable } => {
            // An out-of-order Frame clears the channel's in-progress chain
            // (pico clears the dbuf + state, multicast/rx.c): the dropped frame
            // may have superseded the chain's continuation.
            if let Some(idx) = dispatcher.peer_index_by_src(src) {
                // Multicast QoS conduits are deferred (R311y215 step 8): DEFAULT.
                reasm.abort_channel(
                    &multicast_chain_key(idx),
                    crate::qos::Priority::DEFAULT,
                    reliable,
                );
            }
        }
        MulticastRxNext::Fragment => {
            // SN-gate per peer, reassemble per (slot, channel) chain; a
            // completed chain fans the SAME FramePayload Poll a whole Frame does
            // (zenoh-pico `_z_multicast_handle_fragment_inner`).
            if let Ok(InboundFrame::Fragment {
                reliable,
                sn,
                more,
                payload,
                priority,
                ..
            }) = parse_inbound(bytes)
            {
                // R311y227 — the fragment's decoded `ext_qos` band selects its
                // per-priority conduit gate + reassembly chain (DEFAULT for a
                // non-qos peer, so the pre-R311y227 path is unchanged).
                ingest_multicast_fragment_qos(
                    dispatcher, reasm, src, reliable, sn, more, priority, &payload, now_ms,
                    on_event,
                );
            }
        }
        MulticastRxNext::Close => {
            // The departing peer's in-progress chains die with it BEFORE its
            // slot index can recycle (pico's per-entry dbufs).
            if let Some(idx) = dispatcher.peer_index_by_src(src) {
                abort_peer_chains(reasm, idx);
            }
            dispatcher.close_by_src(src);
        }
    }
}

/// The reassembly-aware multicast sweep tick: reclaim stalled reassembly chains
/// past their deadline (surfacing the timed-out count as an
/// [`IterationEvent::ReassemblyTimeout`]) THEN evict leased-out peers, aborting
/// each evicted slot's chains before its index recycles. The reassembly twin of
/// the bare [`MulticastDispatcher::sweep`] — R311mh extracts it so the AP
/// `multicast_glue` and MCU `multicast_drive` loops stop hand-mirroring the
/// identical `sweep_reporting` + `sweep_with(abort_peer_chains)` pair. A
/// non-reassembly loop calls the bare `sweep` instead.
#[cfg(all(feature = "reassembly", feature = "alloc"))]
pub fn sweep_multicast_reassembling<
    F,
    const MAX_PEERS: usize,
    const SLOTS: usize,
    const CAP: usize,
>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP>,
    now_ms: u64,
    on_event: &mut F,
) where
    F: FnMut(IterationEvent<'_>),
{
    crate::reassembly_dispatch::sweep_reporting(reasm, now_ms, on_event);
    dispatcher.sweep_with(now_ms, |idx| abort_peer_chains(reasm, idx));
}

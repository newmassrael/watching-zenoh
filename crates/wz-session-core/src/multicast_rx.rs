// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use crate::multicast_peer_lost::MulticastPeerLostReason;
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
    FrameOutOfOrder {
        reliable: bool,
        /// R311y227 — the rejected frame's decoded QoS band, so the reassembly
        /// tail aborts THAT priority conduit's in-progress chain (a qos peer's
        /// per-priority chains gate independently). DEFAULT for a non-qos frame,
        /// so the abort targets the single DEFAULT chain as before.
        priority: crate::qos::Priority,
    },
    /// A `T_MID_CLOSE`: the caller calls `close_by_src` (a reassembly caller
    /// aborts the peer's chains FIRST, before the slot index can recycle).
    Close,
    /// A `T_MID_FRAGMENT`: the caller reassembles it (or drops it when its
    /// reassembly feature is off — pico "Fragment dropped because
    /// fragmentation feature is deactivated").
    Fragment,
}

/// R311y633 (§17.6) — how many bytes the message at the front of `msg`
/// occupies, when that is knowable AND another message can follow it.
///
/// `None` means the walk over this framing unit ends here: either the message
/// consumes the remainder by construction, or its extent is unknown and a walk
/// that guessed would dispatch bytes parsed out of the middle of something.
fn multicast_message_len(msg: &[u8]) -> Option<usize> {
    match msg.first().map(|h| h & 0x1f) {
        // A Frame or a Fragment reads to the end of its unit by construction
        // (`zenoh-codec-1.5.0/src/transport/frame.rs:173`), which is why a real
        // batch ends with one. Answered from the MID alone so an admitted data
        // frame is never parsed a second time just to be told it was last.
        Some(wire_const::T_MID_FRAME) | Some(wire_const::T_MID_FRAGMENT) => None,
        _ => crate::inbound::parse_inbound_consuming(msg)
            .ok()
            .map(|(_, consumed)| consumed)
            .filter(|consumed| *consumed > 0 && *consumed < msg.len()),
    }
}

/// R311y633 (§17.6) — dispatch EVERY transport message the datagram carried.
///
/// # Why a datagram is not a message
///
/// This is the path zenoh's own batch loop is written for: its multicast rx
/// reads `while !batch.is_empty()` over a received unit
/// (`zenoh-transport-1.5.0/src/multicast/rx.rs:287`), and pico does not even
/// re-read the link while its buffer still holds bytes
/// (`vendor/zenoh-pico/src/transport/multicast/rx.c:68-77`, advancing by one
/// message at `:99`). Batching is on by default in zenoh's transmission
/// pipeline (`common/pipeline.rs:318` holds the batch instead of flushing it),
/// so a group member's data frame batched behind its keepalive or its JOIN was
/// being dropped here.
///
/// The walk stops at the first message whose verdict is not
/// [`MulticastRxNext::Done`]: `Frame` and `Fragment` consume the remainder, and
/// a `Close` ends the peer whose later messages would otherwise re-admit it.
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
    let mut pos = 0usize;
    loop {
        let msg = &bytes[pos..];
        let next = dispatch_multicast_message(dispatcher, params, msg, src, now_ms, on_event);
        if !matches!(next, MulticastRxNext::Done) {
            return next;
        }
        match multicast_message_len(msg) {
            Some(consumed) => pos += consumed,
            None => return MulticastRxNext::Done,
        }
    }
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
fn dispatch_multicast_message<F, const MAX_PEERS: usize>(
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
                            // Admit unless the peer is qos AND this node is not
                            // (the ONE refused case): `peer_non_qos || local_qos`.
                            if qos_next_sns.is_none() || params.is_qos {
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
                    } else {
                        // R2379 (open-debt item 15, `session-multicast`) — the
                        // JOIN named capabilities this node cannot speak, and
                        // `validate_join` has already applied pico's exact
                        // discriminator (version, `seq_num_res`, `req_id_res`,
                        // `batch_size`, each against OUR OWN params). For an
                        // UNKNOWN address that is simply a refused admission,
                        // which is what this arm has always done. For an
                        // ALREADY-ADMITTED one it is not: the peer is on the
                        // group and changed the terms mid-session, and holding
                        // it to its lease means mis-parsing everything it sends
                        // until the lease runs out.
                        //
                        // pico DROPS it here (`src/transport/multicast/rx.c`,
                        // the existing-peer branch, which updates SNs and lease
                        // only when all three match). zenoh does NOT -- its
                        // `handle_join_from_peer` ignores the inconsistent Join
                        // and keeps the first-announced parameters. The two
                        // upstreams disagree and wz follows pico, for the same
                        // reachability reason recorded on
                        // `MulticastPeerLostReason::CapabilitiesChanged`.
                        //
                        // `drop_by_src_with` is a no-op when nothing is
                        // admitted at `src`, so the unknown-address case needs
                        // no guard here -- the departure event cannot be
                        // manufactured for a peer that never existed.
                        dispatcher.drop_by_src_with(
                            src,
                            MulticastPeerLostReason::CapabilitiesChanged,
                            |lost| on_event(IterationEvent::MulticastPeerLost(lost)),
                        );
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
                    FrameIngest::OutOfOrder => {
                        MulticastRxNext::FrameOutOfOrder { reliable, priority }
                    }
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
    S,
>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP, S>,
    params: &MulticastParams,
    bytes: &[u8],
    src: SocketAddr,
    now_ms: u64,
    on_event: &mut F,
) where
    S: crate::chain_staging::ChainStaging<SLOTS, CAP>,
    F: FnMut(IterationEvent<'_>),
{
    // R311y633 (§17.6) — the SAME walk as the plain entry point, but the tail
    // has to run per MESSAGE: the `Fragment` arm re-parses the bytes it was
    // handed, and parsing from the front of the DATAGRAM would read the message
    // at offset zero instead of the one that produced the verdict.
    let mut pos = 0usize;
    loop {
        let msg = &bytes[pos..];
        match dispatch_multicast_message(dispatcher, params, msg, src, now_ms, on_event) {
            MulticastRxNext::Done => match multicast_message_len(msg) {
                Some(consumed) => {
                    pos += consumed;
                    continue;
                }
                None => return,
            },
            MulticastRxNext::FrameOutOfOrder { reliable, priority } => {
                // An out-of-order Frame clears the channel's in-progress chain
                // (pico clears the dbuf + state, multicast/rx.c): the dropped frame
                // may have superseded the chain's continuation. R311y227 — abort the
                // SAME (peer, priority, reliable) chain the rejected frame's band
                // would have continued, so a qos peer's OTHER-priority chains are
                // untouched. DEFAULT for a non-qos frame (byte-identical to before).
                if let Some(idx) = dispatcher.peer_index_by_src(src) {
                    reasm.abort_channel(&multicast_chain_key(idx), priority, reliable);
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
                }) = parse_inbound(msg)
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
                // R311y784 — an ANNOUNCED departure. Distinguished from the
                // sweep's inferred one at the observer, because a peer saying
                // "I am leaving" and a peer that stopped answering are
                // different facts about the network.
                dispatcher.close_by_src_with(src, |lost| {
                    on_event(IterationEvent::MulticastPeerLost(lost));
                });
            }
        }
        // Every arm above is terminal for this unit: a Frame or a Fragment ate
        // the remainder, and a Close ended the peer that the bytes behind it
        // would otherwise re-admit.
        return;
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
    S,
>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP, S>,
    now_ms: u64,
    on_event: &mut F,
) where
    S: crate::chain_staging::ChainStaging<SLOTS, CAP>,
    F: FnMut(IterationEvent<'_>),
{
    crate::reassembly_dispatch::sweep_reporting(reasm, now_ms, on_event);
    // R311y784 — the two arguments serve two different consumers and both are
    // used here: the slot INDEX aborts this node's own chains (private
    // bookkeeping), the DEPARTURE tells the application which peer went quiet.
    // Before this round only the first existed, so a lease expiry reclaimed
    // buffers silently and the app kept a dead peer forever.
    dispatcher.sweep_with(now_ms, |idx, lost| {
        abort_peer_chains(reasm, idx);
        on_event(IterationEvent::MulticastPeerLost(lost));
    });
}

#[cfg(all(test, feature = "session-multicast", feature = "codec-join"))]
mod batch_walk_tests {
    use super::*;
    use crate::multicast_dispatch::MulticastConfig;
    use crate::multicast_join::encode_join;
    use crate::sn::{self, MulticastTxConduits};
    use alloc::vec::Vec;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use wz_codecs::whatami::WhatAmI;

    const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7447);

    fn params(zid: &[u8]) -> MulticastParams {
        MulticastParams {
            version: 0x09,
            whatami: WhatAmI::Peer,
            zid: zid.to_vec(),
            lease_ms: 5_000,
            join_interval_ms: 1,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
        }
    }

    /// A peer's beacon, through the REAL encoder so the fixture cannot drift
    /// from what wz emits on the wire.
    fn peer_join(zid: &[u8]) -> Vec<u8> {
        let p = params(zid);
        encode_join(
            &p,
            &MulticastTxConduits::new(sn::mask_from_res(p.seq_num_res)),
        )
    }

    /// One `T_MID_FRAME` at sn 0 carrying no network records — enough to be
    /// FANNED, which is the thing the walk either reaches or does not.
    fn frame_sn0() -> Vec<u8> {
        alloc::vec![
            wire_const::T_MID_FRAME | wz_codecs::wire_const::FLAG_T_FRAME_R,
            0x00,
        ]
    }

    fn running<const N: usize>() -> MulticastDispatcher<N> {
        let mut d = MulticastDispatcher::<N>::new(MulticastConfig::new(5_000));
        d.create();
        d.notify_link_ready();
        d
    }

    /// R311y633 (§17.6) — a multicast datagram carrying a JOIN AND a data
    /// frame delivers BOTH.
    ///
    /// # Why this shape
    ///
    /// It is the batch this path exists to receive: zenoh's multicast rx is
    /// where the `while !batch.is_empty()` loop lives
    /// (`zenoh-transport-1.5.0/src/multicast/rx.rs:287`), and its transmission
    /// pipeline holds a batch open by default rather than flushing per message
    /// (`common/pipeline.rs:318`). A beacon and a publish leaving together is
    /// therefore ordinary, and before this round the frame behind the beacon
    /// was dropped without a trace — the peer was admitted and its data was
    /// not.
    ///
    /// The JOIN must come FIRST for the frame to be admitted at all (the SN
    /// gate has no conduit for an unknown peer), which is also why the two
    /// halves cannot be checked separately: the frame's delivery PROVES the
    /// walk continued past a message that had already been fully handled.
    #[test]
    fn a_multicast_datagram_carrying_a_join_and_a_frame_delivers_both() {
        let mut d = running::<4>();
        let local = params(&[0x11; 4]);
        let mut unit = peer_join(&[0x22; 4]);
        unit.extend_from_slice(&frame_sn0());

        let mut polls = 0usize;
        let next = dispatch_multicast_inbound(&mut d, &local, &unit, PEER, 1_000, &mut |event| {
            if matches!(event, IterationEvent::Poll(_)) {
                polls += 1;
            }
        });

        assert!(
            matches!(next, MulticastRxNext::Done),
            "both messages were handled here; got {next:?}"
        );
        assert!(
            d.peer_index_by_src(PEER).is_some(),
            "the JOIN at the front admitted the peer"
        );
        assert_eq!(
            polls, 1,
            "the frame BEHIND the beacon must be fanned: a walk that stopped \
             at the JOIN reports zero"
        );
    }

    /// R311y633 (§17.6) — and the walk stops where the extent is unknown
    /// rather than dispatching bytes it cannot place.
    ///
    /// `0x00` is no transport MID, so nothing can say where that candidate
    /// ends; the JOIN in front of it is still handled.
    #[test]
    fn a_tail_whose_extent_is_unknown_stops_the_walk_without_dispatching_it() {
        let mut d = running::<4>();
        let local = params(&[0x11; 4]);
        let mut unit = peer_join(&[0x22; 4]);
        unit.extend_from_slice(&[0x00, 0x11, 0x22]);

        let mut polls = 0usize;
        let next = dispatch_multicast_inbound(&mut d, &local, &unit, PEER, 1_000, &mut |event| {
            if matches!(event, IterationEvent::Poll(_)) {
                polls += 1;
            }
        });

        assert!(matches!(next, MulticastRxNext::Done), "{next:?}");
        assert!(d.peer_index_by_src(PEER).is_some(), "the JOIN still landed");
        assert_eq!(polls, 0, "and nothing was invented from the tail");
    }
}

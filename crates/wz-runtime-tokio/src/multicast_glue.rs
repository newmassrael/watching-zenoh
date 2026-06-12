// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round C — multicast transport <-> multicast-link drive loop.
//!
//! The AP host loop that drives the engine-free
//! [`MulticastDispatcher`](wz_session_core::multicast_dispatch::MulticastDispatcher)
//! (the session-fsm §3.1 session-level FSM + the §3.2 per-peer table,
//! landed in wz-session-core) against a real UDP-multicast link. This is
//! the multicast sibling of [`crate::scouting_glue`]; the same engine-free
//! split applies — the dispatcher owns the protocol FSMs + the peer-table
//! arithmetic, and this loop owns the socket IO + the clock.
//!
//! ## What the loop owns (the §3.1 Running parallel concerns)
//!
//! §3.1 describes Running as three parallel regions; the SCE surface has no
//! `<parallel>`, so (as the dispatcher's module docs record) the host loop
//! realises them. The JOIN wire functions themselves (encode / decode /
//! validate) are NOT here — R311kt hoisted them to
//! [`wz_session_core::multicast_join`] (pure, shared with the MCU
//! profile, the multicast sibling of `handshake_encode`); this loop owns
//! only the IO and the clock around them:
//! - **JoinEmit** — multicasts a periodic JOIN beacon every
//!   [`MulticastParams::join_interval_ms`]. JOIN is the handshake-free
//!   transport's self-advertisement (the multicast analogue of INIT+OPEN);
//!   there is no separate keepalive, so the periodic JOIN IS the liveness
//!   beacon.
//! - **RxDispatch** — classifies each inbound datagram by its transport MID
//!   and attributes it by the datagram SOURCE ADDRESS (carried on the
//!   [`RxFrame`](wz_session_core::link::RxFrame), populated by the multicast
//!   `UdpDriver`): JOIN -> validate (§3.2 rejection rules) +
//!   [`ingest_join`](MulticastDispatcher::ingest_join) (admit / refresh by
//!   addr, record zid, seed the RX SN baselines); Frame -> the A1b DATA
//!   plane (below); Fragment -> the R311kn reassembly arm
//!   (`reassembly`-gated:
//!   [`ingest_multicast_fragment`](wz_session_core::multicast_dispatch::ingest_multicast_fragment)
//!   SN-gates per peer, reassembles per (slot, channel) chain, and fans
//!   the completed message through the same observer event the Frame arm
//!   uses; without the feature the MID is dropped — pico "Fragment
//!   dropped because fragmentation feature is deactivated"); KeepAlive ->
//!   [`refresh_by_src`](MulticastDispatcher::refresh_by_src); Close ->
//!   [`close_by_src`](MulticastDispatcher::close_by_src) (chains aborted
//!   first — pico's per-entry dbufs die with the peer entry).
//! - **PeerSweep** — evicts peers past their hold window via
//!   [`MulticastDispatcher::sweep`] (R311ks: each peer is held for the
//!   lease ITS JOIN advertised, capped by the local config bound —
//!   zenoh-pico `entry->_lease`, multicast/rx.c:393).
//!
//! ## A1b — the multicast DATA plane (§3.1 `Frame -> per-peer RxDispatch`)
//!
//! An inbound `T_MID_FRAME` from a live peer is decoded
//! ([`parse_inbound`]), admitted against that peer's per-channel SN gate
//! ([`ingest_frame_by_src`](MulticastDispatcher::ingest_frame_by_src) — the
//! §2.3 half-window rule, zenoh-pico `_z_multicast_handle_frame`), and its
//! NetworkMessage batch ([`parse_frame_payload`]) is fanned to the caller's
//! `on_event` observer callback as an
//! [`IterationEvent::Poll`]`(`[`DriverLoopOutcome::FramePayload`]`)` — the
//! SAME event shape the unicast
//! [`drive_session_until_terminal`](crate::session_glue::drive_session_until_terminal)
//! loop fans, so one
//! [`ApplicationLayerObserver`](wz_session_core::observer::ApplicationLayerObserver)
//! routes both transports' data into the subscriber / queryable / reply
//! registries (zenoh-pico parity: multicast frames reach the same
//! `_z_handle_network_message` the unicast transport calls). A frame from
//! an address that never JOINed is dropped (pico "Dropping _Z_FRAME from
//! unknown peer"); a malformed frame is dropped without touching the
//! session FSM (one bad peer must not tear down the group — unlike the
//! unicast loop's `FramingError`).
//!
//! ## RX attribution: by source address (zenoh-pico parity)
//!
//! Frame / KeepAlive / Close carry NO sender zid on the wire, so — exactly
//! like zenoh-pico (`_z_find_peer_entry(addr)`) — every inbound message is
//! attributed to a peer by its datagram source address. JOIN additionally
//! carries the announcer's zid, recorded as the peer's protocol identity.
//! The `RxFrame.src` field carries the address; a non-multicast link leaves
//! it `None` and such messages are ignored here.
//!
//! ## Stop
//!
//! The loop runs until the link is lost (`LinkEvent::Lost` ->
//! [`MulticastOutcome::LinkLost`]) or the test iteration budget is reached.
//! A graceful `multicast.stop` (the §3.1 Running -> Stopped event) needs a
//! shutdown signal threaded into the `select!`; that is a deferred
//! follow-up (Round C drives until link loss).

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[cfg(feature = "reassembly")]
use wz_session_core::drive::sweep_reporting;
use wz_session_core::driver_loop::IterationEvent;
// R311lr — the declarer-side liveliness interest-response reply builders the
// AP loop's `MulticastReplySink` composes before enqueuing a
// `MulticastTxItem::DeclareReply` (the borrowed-keyexpr `build_*_reply` SSOT,
// the same wire shape the unicast `SessionLinkActions: DeclareReplySink`
// derives). Gated on `liveliness-token` (the sole producer). The Frame
// encoders + the egress splitter moved to the shared
// `wz_session_core::multicast_tx` SSOT (R311lx); this loop no longer names
// them.
#[cfg(feature = "liveliness-token")]
use wz_session_core::declare::local_token::{build_final_reply, build_token_reply};
// R311lv — the inbound Frame codec is now only named in this loop's
// reassembly Fragment tail (the JOIN / Frame classify moved to the shared
// `multicast_rx` SSOT); the tests import their own copy.
#[cfg(feature = "reassembly")]
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_core::link::{LinkEvent, TxFrame};
use wz_session_core::multicast_dispatch::MulticastDispatcher;
#[cfg(feature = "reassembly")]
use wz_session_core::multicast_dispatch::{
    abort_peer_chains, ingest_multicast_fragment, multicast_chain_key,
};
use wz_session_core::multicast_join::encode_join;
use wz_session_core::multicast_rx::{dispatch_multicast_inbound, MulticastRxNext};
// R311lx — the shared TX emit SSOT: the item-variant -> mint -> encode ->
// fragment decision the loop's outbound arm used to carry inline. The enum +
// the `multicast_put_literal` builder are re-exported so the loop's public TX
// API (and its tests) are unchanged by the move.
#[cfg(feature = "codec-push")]
pub use wz_session_core::multicast_tx::multicast_put_literal;
pub use wz_session_core::multicast_tx::MulticastTxItem;
// The emit SSOT exists only when a TX body codec inhabits `MulticastTxItem`;
// gated on that union so a (degenerate) multicast-without-data build still
// compiles — the loop's outbound arm consumes the then-uninhabited item with an
// empty match instead of naming the gated-out `multicast_tx_emit`.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
use wz_session_core::multicast_tx::multicast_tx_emit;
use wz_session_core::reliability::Reliability;
use wz_session_core::session_fsm_multicast::SessionFsmMulticastState;
use wz_session_core::sn::{self, TxSn};

use wz_runtime_core::TimeSource;

use crate::LinkDriver;

// R311lx — `MulticastTxItem` moved to the shared `wz_session_core::multicast_tx`
// SSOT (the TX twin of the `multicast_rx` RX SSOT) and is re-exported above, so
// this loop's public TX API is unchanged by the move. The per-variant
// mint/encode/fragment orchestration the outbound arm carried inline now lives
// in `multicast_tx_emit`.

/// R311lq/R311lr — the multicast drive loop's observer-drain sink, backed by
/// its A1c outbound channel. The application's `on_event` closure drains its
/// observer's staged outbound effects through this sink; each emit enqueues a
/// [`MulticastTxItem`] that [`drive_multicast_session`] frames into a
/// `T_MID_FRAME` and multicasts to the group — the multicast mirror of the
/// unicast `SessionLinkActions`, which enqueues onto the per-peer writer
/// channel instead.
///
/// Per the R311lq interface segregation it implements EXACTLY the two
/// observer-drain concerns the multicast loop actually uses, as separate
/// impl blocks:
/// - [`ResponseSink`](wz_session_core::response_sink::ResponseSink) — the
///   queryable reply chain (`observer.flush_query_replies(&sink)`).
/// - [`DeclareReplySink`](wz_session_core::response_sink::DeclareReplySink)
///   — R311lr, the declarer-side liveliness interest-response
///   (`observer.flush_declare_replies(&sink)`): a held token's
///   `Declare(DeclToken)` + terminating `DeclFinal` reply to a peer's
///   liveliness Interest that arrived on the group.
///
/// It deliberately does NOT implement
/// [`LivelinessGetPrune`](wz_session_core::response_sink::LivelinessGetPrune).
/// That concern is the session-reconnect declaration-cache prune (F3), and
/// the connectionless multicast transport (JOIN + lease, never a re-dial) has
/// no reconnect cache — so there is genuinely nothing to prune. Honoring the
/// segregation, the loop implements only the concerns it drains rather than
/// stubbing an empty `LivelinessGetPrune` to reach the fat `flush_pending`.
/// `Clone` so the closure can hold a sender clone while the loop owns the
/// paired receiver.
#[derive(Clone)]
pub struct MulticastReplySink {
    tx: UnboundedSender<MulticastTxItem>,
}

impl MulticastReplySink {
    /// Wrap a clone of the loop's outbound-channel sender as a reply sink.
    pub fn new(tx: UnboundedSender<MulticastTxItem>) -> Self {
        Self { tx }
    }
}

impl wz_session_core::response_sink::ResponseSink for MulticastReplySink {
    #[cfg(feature = "codec-response")]
    fn send_response(&self, response: wz_codecs::response::ResponseOwned) {
        // Fire-and-forget, mirroring `SessionLinkActions::send_response`'s
        // F2 contract (no error channel): a dropped receiver (the loop
        // ended) drops the reply exactly as a dead link would.
        let _ = self.tx.send(MulticastTxItem::Response { response });
    }
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(&self, request_id: u64) {
        let _ = self.tx.send(MulticastTxItem::ResponseFinal { request_id });
    }
}

// R311lr — the declarer-side liveliness interest-response drain. The observer
// stages a held token's reply (token id + interest id) and resolves the
// keyexpr from its registry at drain, then hands this sink the borrowed
// (token_id, keyexpr, interest_id); the sink owns the encode by building the
// owned `Declare` form via the shared `build_*_reply` SSOT (the same wire
// shape the unicast `SessionLinkActions: DeclareReplySink` derives) and
// enqueues it. A separate impl block from `ResponseSink` per the R311lq
// segregation — a declare reply is a distinct message family from a query
// `Response`.
impl wz_session_core::response_sink::DeclareReplySink for MulticastReplySink {
    #[cfg(feature = "liveliness-token")]
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
        let declare = build_token_reply(token_id, keyexpr, interest_id)
            .try_into_owned()
            .expect("local-token reply keyexpr is within MAX_KEYEXPR_BYTES");
        let _ = self.tx.send(MulticastTxItem::DeclareReply { declare });
    }
    #[cfg(feature = "liveliness-token")]
    fn send_declare_final_reply(&self, interest_id: u64) {
        let declare = build_final_reply(interest_id)
            .try_into_owned()
            .expect("DeclFinal reply carries no bounded fields");
        let _ = self.tx.send(MulticastTxItem::DeclareReply { declare });
    }
}

// R311lx — `multicast_put_literal` moved to `wz_session_core::multicast_tx`
// alongside `MulticastTxItem` (it composes the session-core `build_push_literal`
// SSOT, so it belongs with the shared item type rather than in the AP loop) and
// is re-exported above for API stability.

// R311lt — `MulticastOutcome` moved to the shared SSOT
// `wz_session_core::multicast_params` (consumed by both the AP and MCU
// multicast loops); re-exported so existing `multicast_glue::MulticastOutcome`
// import paths still resolve.
pub use wz_session_core::multicast_params::MulticastOutcome;

// R311lt — `MulticastDriveConfig` moved to the shared SSOT
// `wz_session_core::multicast_params` (consumed by both this AP loop and the
// MCU `wz_session_lwip::multicast_drive::run_multicast_session`); re-exported
// here so existing `multicast_glue::MulticastDriveConfig` import paths still
// resolve.
pub use wz_session_core::multicast_params::MulticastDriveConfig;

/// Drive a multicast session: bring the link up, then own the §3.1 Running
/// concerns (periodic JOIN emit, RX classify -> dispatch + the A1b data
/// plane, lease sweep) until the link is lost or `cfg.max_iters` is reached.
///
/// `cfg` ([`MulticastDriveConfig`]) bundles the loop's static configuration
/// — the protocol `params`, the scheduler `tick_ms` cadence, and the
/// test-only `max_iters` budget — separated from the runtime handles below.
/// `max_iters` bounds the select loop for tests; production passes `None`.
/// `tick_ms` is the scheduler cadence (the JOIN interval + lease are
/// spec-sourced from `params` / the dispatcher config, not duplicated
/// here). The loop owns the monotonic clock (the engine-free FSMs bind
/// `NoOpHal` and arm no timer — same split as [`crate::scouting_glue`]).
///
/// `on_event` is the per-iteration observer callback (the multicast mirror
/// of `drive_session_until_terminal`'s): each SN-admitted data Frame fans
/// one [`IterationEvent::Poll`]`(`[`DriverLoopOutcome::FramePayload`]`)`
/// carrying the decoded NetworkMessage batch. Wire it to
/// `ApplicationLayerObserver::dispatch` (exactly as the unicast loop does)
/// to route multicast pub/sub data into the registered subscriber /
/// queryable registries.
///
/// `outbound` is the A1c TX seam: queued [`MulticastTxItem`]s are framed
/// with a freshly minted per-channel SN (the loop-owned [`TxSn`] the JOIN
/// beacon also advertises) and multicast to the group; a frame past the
/// group batch budget leaves as a `T_MID_FRAGMENT` chain instead (R311ko,
/// [`multicast_frame_or_fragments`](wz_session_core::frame_encode::multicast_frame_or_fragments)
/// — the chain rides the minted SN and the follow-on mints). A
/// publish-free caller passes the receiver of an
/// idle channel; when every sender is dropped the arm disarms (the loop
/// keeps serving RX + JOIN).
pub async fn drive_multicast_session<D, T, F, const MAX_PEERS: usize>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    cfg: MulticastDriveConfig<'_>,
    driver: &mut D,
    clock: &T,
    mut on_event: F,
    outbound: &mut UnboundedReceiver<MulticastTxItem>,
) -> MulticastOutcome
where
    D: LinkDriver,
    T: TimeSource,
    F: FnMut(IterationEvent<'_>),
{
    // Destructure into the same local names the loop body uses, so the body
    // is unchanged by the Introduce-Parameter-Object refactor.
    let MulticastDriveConfig {
        params,
        tick_ms,
        max_iters,
    } = cfg;
    // Idle -> LinkOpening -> Running.
    dispatcher.create();
    dispatcher.notify_link_ready();

    // Emit the first JOIN beacon immediately, then every join_interval_ms.
    let mut next_join_ms = clock.now_monotonic_ms();

    // The TX mint state (per-channel next SN). The JOIN beacon advertises
    // the live values; every outbound data frame mints from here.
    let mut tx_sn = TxSn::new(sn::mask_from_res(params.seq_num_res));
    // R311kn — the loop owns the multicast reassembly Router: per-peer
    // fragment chains keyed by the peer's pool-slot index (zenoh-pico's
    // per-entry dbuf pair, generalised to the bounded §5.M slot pool).
    // Same SCE-sourced AP pool dims/knobs as the unicast loop — one
    // buffer-pool policy SSOT, two transports.
    #[cfg(feature = "reassembly")]
    let mut reasm =
        crate::session_glue::TokioReassembly::new(crate::session_glue::reassembly_config());
    // Once every sender is dropped `recv()` would resolve `None` forever;
    // disarm the select arm instead of busy-looping on it.
    let mut outbound_open = true;

    let mut iter: usize = 0;
    loop {
        if dispatcher.session_state() != SessionFsmMulticastState::Running {
            return MulticastOutcome::Stopped;
        }
        if let Some(limit) = max_iters {
            if iter >= limit {
                return MulticastOutcome::IterationLimit;
            }
            iter += 1;
        }

        // JoinEmit: multicast the self-advertising JOIN beacon when due.
        let now = clock.now_monotonic_ms();
        if now >= next_join_ms {
            let dgram = encode_join(params, &tx_sn);
            let frame = TxFrame { bytes: &dgram };
            // Best-effort: a failed multicast send is non-fatal (the next
            // cadence retries), so unlike the scout path there is no
            // tx-failed transition to drive.
            let _ = driver.send(&frame, Reliability::BestEffort).await;
            next_join_ms = now.saturating_add(params.join_interval_ms);
        }

        tokio::select! {
            item = outbound.recv(), if outbound_open => match item {
                // R311lx — hand the item to the shared TX emit SSOT (mint ->
                // encode_frame_with_* -> fragment, the decision the four inline
                // arms used to carry); multicast each returned datagram on this
                // loop's driver. The SSOT pins reliability per variant (Push by
                // its flag; Response / ResponseFinal / DeclareReply reliable).
                // Send failure is non-fatal like the JOIN beacon — UDP multicast
                // is best-effort; the SN gap a dropped datagram leaves stays
                // inside receivers' half-window (a hole in a fragment chain
                // aborts that chain at every receiver, as on pico).
                #[cfg(any(
                    feature = "codec-push",
                    feature = "codec-response",
                    feature = "codec-response-final",
                    feature = "liveliness-token"
                ))]
                Some(item) => {
                    let frames = multicast_tx_emit(item, &mut tx_sn, params);
                    let reliability = if frames.reliable {
                        Reliability::Reliable
                    } else {
                        Reliability::BestEffort
                    };
                    for dgram in frames.datagrams {
                        let frame = TxFrame { bytes: &dgram };
                        let _ = driver.send(&frame, reliability).await;
                    }
                }
                // No TX body codec: `MulticastTxItem` is uninhabited, so `recv()`
                // can only yield `None`; consume the unconstructable item with an
                // empty match to keep the arm exhaustive without naming the
                // gated-out emit SSOT.
                #[cfg(not(any(
                    feature = "codec-push",
                    feature = "codec-response",
                    feature = "codec-response-final",
                    feature = "liveliness-token"
                )))]
                Some(item) => match item {},
                None => outbound_open = false,
            },
            event = driver.poll_event() => match event {
                LinkEvent::Rx(rx) => {
                    // RxDispatch: every multicast message is attributed by its
                    // datagram SOURCE ADDRESS (the peer key — Frame / KeepAlive
                    // / Close carry no zid on the wire). A multicast UdpDriver
                    // always carries the src; without it (a non-multicast link)
                    // nothing can be attributed, so the message is ignored.
                    if let Some(src) = rx.src {
                        let now = clock.now_monotonic_ms();
                        // R311lv — the JOIN admit / Frame admit-and-fan / KeepAlive
                        // refresh are the shared `wz_session_core` RxDispatch SSOT
                        // (one home for both the AP + MCU loops). This loop owns
                        // only the reassembly-divergent tail it hands back.
                        match dispatch_multicast_inbound(
                            dispatcher,
                            params,
                            &rx.bytes,
                            src,
                            now,
                            &mut on_event,
                        ) {
                            MulticastRxNext::Done => {}
                            MulticastRxNext::FrameOutOfOrder { reliable } => {
                                // R311kn — an out-of-order FRAME clears the
                                // channel's in-progress reassembly chain (pico
                                // clears the dbuf + state, multicast/rx.c
                                // `_z_multicast_handle_frame`): the dropped frame
                                // may have superseded the chain's continuation, so
                                // completing it would mix generations.
                                #[cfg(feature = "reassembly")]
                                if let Some(idx) = dispatcher.peer_index_by_src(src) {
                                    reasm.abort_channel(&multicast_chain_key(idx), reliable);
                                }
                                #[cfg(not(feature = "reassembly"))]
                                let _ = reliable;
                            }
                            MulticastRxNext::Close => {
                                // Graceful departure (attributed by source
                                // address). R311kn — the departing peer's
                                // in-progress chains die with it (pico's per-entry
                                // dbufs), BEFORE the slot index can be re-issued.
                                #[cfg(feature = "reassembly")]
                                if let Some(idx) = dispatcher.peer_index_by_src(src) {
                                    abort_peer_chains(&mut reasm, idx);
                                }
                                dispatcher.close_by_src(src);
                            }
                            MulticastRxNext::Fragment => {
                                // R311kn — the multicast fragment RX arm: SN-gate
                                // per peer, reassemble per (slot, channel) chain,
                                // and fan the completed message through the SAME
                                // observer event the Frame arm uses (zenoh-pico
                                // `_z_multicast_handle_fragment_inner`). Without
                                // `reassembly` the fragment is dropped — pico
                                // "Fragment dropped because fragmentation feature
                                // is deactivated".
                                #[cfg(feature = "reassembly")]
                                if let Ok(InboundFrame::Fragment {
                                    reliable,
                                    sn,
                                    more,
                                    payload,
                                    ..
                                }) = parse_inbound(&rx.bytes)
                                {
                                    ingest_multicast_fragment(
                                        dispatcher,
                                        &mut reasm,
                                        src,
                                        reliable,
                                        sn,
                                        more,
                                        &payload,
                                        now,
                                        &mut on_event,
                                    );
                                }
                            }
                        }
                    }
                }
                LinkEvent::Lost { cause } => {
                    dispatcher.notify_link_lost();
                    return MulticastOutcome::LinkLost(cause);
                }
                LinkEvent::Ready => {}
            },
            _ = clock.sleep(tick_ms) => {
                // PeerSweep: evict peers past their lease. Swept every tick
                // (>= the §3.1 lease/3 cadence; sweeping more often only
                // sharpens eviction, and sweep is idempotent). R311kn — an
                // evicted peer's chains are aborted before its slot index
                // recycles, and the reassembly deadline sweep runs on the
                // same tick (the unicast loop's per-iteration twin).
                let now = clock.now_monotonic_ms();
                #[cfg(feature = "reassembly")]
                {
                    sweep_reporting(&mut reasm, now, &mut on_event);
                    dispatcher.sweep_with(now, |idx| abort_peer_chains(&mut reasm, idx));
                }
                #[cfg(not(feature = "reassembly"))]
                dispatcher.sweep(now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::collections::VecDeque;

    use wz_session_core::inbound::{parse_inbound, InboundFrame};
    use wz_session_core::link::{LostCause, RxFrame};
    use wz_session_core::multicast_dispatch::MulticastConfig;
    use wz_session_core::multicast_join::decode_join;
    use wz_session_core::multicast_params::MulticastParams;
    use wz_session_core::multicast_peer::MulticastPeerState;
    use wz_session_core::network_message::parse_frame_payload;
    use wz_session_core::wire_const;

    use crate::runtime_impl::TokioTime;

    /// A distinct peer source address (the addr-keyed peer-table primary key).
    fn src(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn params(zid: &[u8]) -> MulticastParams {
        MulticastParams {
            version: 0x09,
            whatami: 0x01, // PEER (wire form)
            zid: zid.to_vec(),
            lease_ms: 5_000,
            join_interval_ms: 1,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
        }
    }

    /// A fresh announcer's JOIN datagram (both advertised next SNs = 0) —
    /// the membership fixtures only need SOME valid beacon.
    fn join0(p: &MulticastParams) -> Vec<u8> {
        encode_join(p, &TxSn::new(sn::mask_from_res(p.seq_num_res)))
    }

    /// A publish-free outbound seam: the sender is dropped immediately, so
    /// the loop disarms the TX arm on first poll.
    fn idle_outbound() -> tokio::sync::mpsc::UnboundedReceiver<MulticastTxItem> {
        tokio::sync::mpsc::unbounded_channel().1
    }
    /// A fake in-memory link driver: replays queued inbound datagrams,
    /// captures sent frames, and (once drained) parks so the loop falls to
    /// the sweep tick. Lets the async drive loop be exercised deterministically
    /// without a real multicast socket (mirrors how the scouting unit tests
    /// cover the deterministic logic; the real-socket path is Layer M).
    struct FakeDriver {
        /// Queued inbound datagrams, each with its source address (the
        /// multicast peer key).
        inbound: VecDeque<(Vec<u8>, SocketAddr)>,
        sent: Vec<Vec<u8>>,
        lost: bool,
    }

    impl FakeDriver {
        fn with(inbound: impl IntoIterator<Item = (Vec<u8>, SocketAddr)>) -> Self {
            Self {
                inbound: inbound.into_iter().collect(),
                sent: Vec::new(),
                lost: false,
            }
        }
    }

    impl LinkDriver for FakeDriver {
        async fn open(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        async fn send(
            &mut self,
            frame: &TxFrame<'_>,
            _reliability: Reliability,
        ) -> std::io::Result<()> {
            self.sent.push(frame.bytes.to_vec());
            Ok(())
        }
        async fn close(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        async fn poll_event(&mut self) -> LinkEvent {
            if self.lost {
                return LinkEvent::Lost {
                    cause: LostCause::PeerClosed,
                };
            }
            if let Some((dg, src)) = self.inbound.pop_front() {
                // A multicast datagram carries its source address.
                return LinkEvent::Rx(RxFrame::with_src(dg, src));
            }
            // Drained: never resolve so `select!` always takes the sweep
            // tick, advancing the loop to its iteration budget.
            core::future::pending().await
        }
    }

    /// The drive loop admits a peer from an inbound JOIN (keyed by its source
    /// address) and emits its own JOIN beacon.
    #[tokio::test]
    async fn drive_loop_admits_join_peer_and_emits_beacon() {
        let peer_b = [0x01, 0x02, 0x03, 0x04];
        let mut driver = FakeDriver::with([(join0(&params(&peer_b)), src(2))]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let outcome = drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                tick_ms: 5,
                max_iters: Some(5),
            },
            // self
            &mut driver,
            &clock,
            |_| {},
            &mut idle_outbound(),
        )
        .await;

        assert_eq!(outcome, MulticastOutcome::IterationLimit);
        // The inbound JOIN admitted peer B (queryable by zid and by src).
        assert_eq!(dispatcher.active_peers(), 1);
        assert_eq!(
            dispatcher.peer_state(&peer_b),
            Some(MulticastPeerState::Active)
        );
        assert_eq!(
            dispatcher.peer_state_by_src(src(2)),
            Some(MulticastPeerState::Active)
        );
        // At least one self JOIN beacon was multicast, MID-framed correctly
        // (the non-default fixture batch advertises S=1, masked out here).
        assert!(!driver.sent.is_empty(), "expected >= 1 JOIN beacon");
        assert_eq!(driver.sent[0][0] & 0x1f, wire_const::T_MID_JOIN);
    }

    /// An inbound Close (attributed by source address) evicts the peer.
    #[tokio::test]
    async fn drive_loop_evicts_peer_on_close() {
        let peer_b = [0x01, 0x02, 0x03, 0x04];
        // First a JOIN from peer B's address admits it, then a Close from the
        // SAME address evicts it — the Close carries no zid, so it is keyed
        // by source address.
        let mut driver = FakeDriver::with([
            (join0(&params(&peer_b)), src(2)),
            (std::vec![wire_const::T_MID_CLOSE, 0x00], src(2)),
        ]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let outcome = drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                tick_ms: 5,
                max_iters: Some(8),
            },
            &mut driver,
            &clock,
            |_| {},
            &mut idle_outbound(),
        )
        .await;

        assert_eq!(outcome, MulticastOutcome::IterationLimit);
        assert_eq!(dispatcher.active_peers(), 0, "Close must evict the peer");
    }

    /// A lost link returns `LinkLost` and clears the peer table (§3.1).
    #[tokio::test]
    async fn drive_loop_returns_link_lost() {
        let mut driver = FakeDriver {
            inbound: VecDeque::new(),
            sent: Vec::new(),
            lost: true,
        };
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let outcome = drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                tick_ms: 5,
                max_iters: Some(5),
            },
            &mut driver,
            &clock,
            |_| {},
            &mut idle_outbound(),
        )
        .await;

        assert!(matches!(outcome, MulticastOutcome::LinkLost(_)));
        assert_eq!(
            dispatcher.session_state(),
            SessionFsmMulticastState::Stopped
        );
        assert_eq!(dispatcher.active_peers(), 0);
    }

    // ── A1b — data plane: Frame payload -> observer registries ──

    /// A JOIN whose version differs from ours is ignored (§3.2 rejection
    /// rules / zenoh-pico proto-version guard): no peer is admitted.
    #[tokio::test]
    async fn drive_loop_ignores_join_with_version_mismatch() {
        let mut peer = params(&[0x01, 0x02, 0x03, 0x04]);
        peer.version = 0x08; // wire-incompatible announcer
        let mut driver = FakeDriver::with([(join0(&peer), src(2))]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                tick_ms: 5,
                max_iters: Some(5),
            },
            &mut driver,
            &clock,
            |_| {},
            &mut idle_outbound(),
        )
        .await;

        assert_eq!(dispatcher.active_peers(), 0, "version mismatch must drop");
    }

    /// A JOIN advertising a different SN resolution is ignored (§3.2
    /// incompatible-config refuse — multicast has no negotiation).
    #[tokio::test]
    async fn drive_loop_ignores_join_with_mismatched_sn_res() {
        use wz_codecs::join::Join;
        let zid = [0x01, 0x02, 0x03, 0x04];
        let mut join = Join::new();
        join.version = 0x09;
        join.set_whatami(0x01);
        join.set_zid_len_m1((zid.len() - 1) as u8);
        join.zid = &zid;
        join.sn_res = Some(0x01); // 14-bit ring, ours is 0x02 (28-bit)
        join.batch_size = Some(0xFFFF);
        join.lease = 5_000;
        let body = join.encode_to_vec(1);
        let mut dgram = std::vec![wire_const::T_MID_JOIN | wire_const::FLAG_T_JOIN_S];
        dgram.extend_from_slice(&body);

        let mut driver = FakeDriver::with([(dgram, src(2))]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                tick_ms: 5,
                max_iters: Some(5),
            },
            &mut driver,
            &clock,
            |_| {},
            &mut idle_outbound(),
        )
        .await;

        assert_eq!(dispatcher.active_peers(), 0, "sn_res mismatch must drop");
    }

    /// The data plane end-to-end inside the loop: a peer JOINs, then its
    /// Frame (at the JOIN-advertised next SN) carrying a Push reaches a
    /// registered subscriber through the SAME `ApplicationLayerObserver`
    /// fan the unicast loop uses. A replay of the same frame is dropped by
    /// the SN gate (the callback fires exactly once), mirroring zenoh-pico
    /// `_z_multicast_handle_frame` -> `_z_handle_network_message`.
    #[cfg(all(feature = "codec-push", feature = "pubsub-put"))]
    #[tokio::test]
    async fn drive_loop_delivers_frame_push_to_subscriber_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use wz_session_core::frame_encode::encode_frame_with_push;
        use wz_session_core::observer::ApplicationLayerObserver;
        use wz_session_core::push_build::build_push_literal;

        let peer_b = [0x01, 0x02, 0x03, 0x04];
        let join = join0(&params(&peer_b)); // next_sn_reliable = 0
        let push = build_push_literal("demo/mc", b"over-multicast").expect("push fixture");
        let frame = encode_frame_with_push(/*sn=*/ 0, push, /*reliable=*/ true);

        // JOIN admits the peer, the first frame is delivered, the replayed
        // frame is SN-stale and dropped.
        let mut driver =
            FakeDriver::with([(join, src(2)), (frame.clone(), src(2)), (frame, src(2))]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let fired = Arc::new(AtomicUsize::new(0));
        let mut observer = ApplicationLayerObserver::new();
        {
            let fired = fired.clone();
            observer.subscribers.register("demo/mc", move |sample| {
                assert_eq!(sample.keyexpr(), "demo/mc");
                assert_eq!(sample.payload(), b"over-multicast");
                fired.fetch_add(1, Ordering::SeqCst);
            });
        }

        let outcome = drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                tick_ms: 5,
                max_iters: Some(8),
            },
            &mut driver,
            &clock,
            |event| observer.dispatch_event(event),
            &mut idle_outbound(),
        )
        .await;

        assert_eq!(outcome, MulticastOutcome::IterationLimit);
        assert_eq!(dispatcher.active_peers(), 1);
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "the Push must reach the subscriber exactly once (replay SN-dropped)"
        );
    }

    /// R311lq — the queryable REPLY plane end-to-end inside the loop: a peer
    /// JOINs, then sends a Query Frame (at the JOIN-advertised next SN)
    /// matching a registered queryable. The observer dispatches the Query to
    /// the handler (which stages a reply), the `on_event` closure drains the
    /// staged reply through `MulticastReplySink` onto the loop's outbound
    /// channel, and the loop frames the `Response` + its terminal
    /// `ResponseFinal` and multicasts them to the group — the multicast mirror
    /// of the unicast queryable reply path (zenoh-pico `_z_send_reply` ->
    /// `_z_send_n_msg` over the multicast transport, src/net/primitives.c).
    #[cfg(all(feature = "query-queryable", feature = "codec-response-final"))]
    #[tokio::test]
    async fn drive_loop_emits_queryable_reply_over_multicast() {
        use wz_session_core::frame_encode::encode_frame_with_request;
        use wz_session_core::network_message::NetworkMessage;
        use wz_session_core::observer::ApplicationLayerObserver;
        use wz_session_core::request_build::build_request_query;

        let peer_b = [0x01, 0x02, 0x03, 0x04];
        let join = join0(&params(&peer_b)); // next_sn_reliable = 0
                                            // A literal-keyexpr Query for "demo/mc", request id 7, on the reliable
                                            // channel at the JOIN-advertised next SN (so the per-peer SN gate
                                            // admits it).
        let query = encode_frame_with_request(
            /*sn=*/ 0,
            build_request_query(7, 0, Some("demo/mc")).expect("query fixture"),
            /*reliable=*/ true,
        );

        let mut driver = FakeDriver::with([(join, src(2)), (query, src(2))]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let mut observer = ApplicationLayerObserver::new();
        observer
            .queryables
            .register("demo/mc", |_query, responder| {
                responder.reply(b"reply-over-multicast");
            });

        // The reply sink shares the loop's outbound channel: the closure
        // enqueues drained replies, the loop drains the channel and frames
        // them onto the group (the A1c TX seam).
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sink = MulticastReplySink::new(tx);

        let outcome = drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                tick_ms: 5,
                max_iters: Some(12),
            },
            &mut driver,
            &clock,
            |event| {
                observer.dispatch_event(event);
                // Drain only the queryable-reply concern — the multicast loop
                // does not (yet) carry the liveliness declare / get-prune
                // planes, so per R311lq it implements only `ResponseSink`.
                observer.flush_query_replies(&sink);
            },
            &mut rx,
        )
        .await;

        assert_eq!(outcome, MulticastOutcome::IterationLimit);
        assert_eq!(dispatcher.active_peers(), 1, "JOIN admitted the querier");

        // Classify the multicast TX: skip the JOIN beacons (not T_MID_FRAME),
        // decode each Frame payload, and tally the reply-chain messages.
        let mut responses = 0usize;
        let mut finals = 0usize;
        for dg in &driver.sent {
            if let Ok(InboundFrame::Frame { payload, .. }) = parse_inbound(dg) {
                if let Ok(messages) = parse_frame_payload(&payload) {
                    for m in &messages {
                        match m {
                            NetworkMessage::Response(_) => responses += 1,
                            NetworkMessage::ResponseFinal(rf) => {
                                assert_eq!(rf.request_id, 7, "Final terminates rid 7's chain");
                                finals += 1;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        assert_eq!(responses, 1, "exactly one Response reached the group");
        assert_eq!(
            finals, 1,
            "exactly one ResponseFinal terminated the reply chain"
        );
    }

    /// R311lr — the declarer-side liveliness DECLARE-reply plane end-to-end
    /// inside the loop: a peer JOINs, then sends a CURRENT liveliness
    /// `Interest` Frame (at the JOIN-advertised next SN) matching a held local
    /// liveliness token. The observer dispatches the Interest to the
    /// `LocalTokenRegistry` (which stages a `Declare(DeclToken)` reply + a
    /// terminating `Declare(DeclFinal)`), the `on_event` closure drains the
    /// staged interest-response through `MulticastReplySink`'s
    /// `DeclareReplySink` impl onto the loop's outbound channel, and the loop
    /// frames the `Declare`s and multicasts them to the group — the multicast
    /// mirror of the unicast declarer interest-response path (zenoh-pico
    /// `_z_send_declare` -> `_z_send_n_msg` over the multicast transport,
    /// src/net/primitives.c:52). The loop drains ONLY the declare-reply
    /// concern (`flush_declare_replies`): no queryable is registered, and the
    /// connectionless multicast transport has no liveliness-get reconnect
    /// cache, so per the R311lq segregation the sink need not satisfy the
    /// `ResponseSink` data-reply nor the `LivelinessGetPrune` concerns here.
    #[cfg(feature = "liveliness-token")]
    #[tokio::test]
    async fn drive_loop_emits_liveliness_token_reply_over_multicast() {
        use wz_codecs::declare::DeclareOwnedVariant;
        use wz_session_core::frame_encode::encode_frame_with_interest;
        use wz_session_core::interest_build::build_interest_liveliness_get;
        use wz_session_core::network_message::NetworkMessage;
        use wz_session_core::observer::ApplicationLayerObserver;

        let peer_b = [0x01, 0x02, 0x03, 0x04];
        let join = join0(&params(&peer_b)); // next_sn_reliable = 0
                                            // A CURRENT liveliness get for "demo/live", interest id 9, on the
                                            // reliable channel at the JOIN-advertised next SN (so the per-peer SN
                                            // gate admits it). mapping_id 0 + literal suffix = a literal keyexpr.
        let interest = encode_frame_with_interest(
            /*sn=*/ 0,
            build_interest_liveliness_get(9, 0, Some("demo/live")).expect("interest fixture"),
            /*reliable=*/ true,
        );

        let mut driver = FakeDriver::with([(join, src(2)), (interest, src(2))]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        // A held local liveliness token at the queried keyexpr — the declarer
        // replies with it (and only it: the sole registered token matches).
        let mut observer = ApplicationLayerObserver::new();
        observer
            .local_tokens
            .register(/*token_id=*/ 3, "demo/live")
            .expect("register held token");

        // The reply sink shares the loop's outbound channel: the closure
        // drains the staged declare interest-response onto it, the loop frames
        // each `Declare` onto the group (the A1c TX seam).
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sink = MulticastReplySink::new(tx);

        let outcome = drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                tick_ms: 5,
                max_iters: Some(12),
            },
            &mut driver,
            &clock,
            |event| {
                observer.dispatch_event(event);
                observer.flush_declare_replies(&sink);
            },
            &mut rx,
        )
        .await;

        assert_eq!(outcome, MulticastOutcome::IterationLimit);
        assert_eq!(dispatcher.active_peers(), 1, "JOIN admitted the querier");

        // Classify the multicast TX: skip the JOIN beacons (not T_MID_FRAME),
        // decode each Frame payload, and tally the declare-reply chain. Both
        // the DeclToken and the terminating DeclFinal carry the get's
        // interest_id (9) — the correlation the querier matches on.
        let mut tokens = 0usize;
        let mut finals = 0usize;
        for dg in &driver.sent {
            if let Ok(InboundFrame::Frame { payload, .. }) = parse_inbound(dg) {
                if let Ok(messages) = parse_frame_payload(&payload) {
                    for m in &messages {
                        if let NetworkMessage::Declare(d) = m {
                            match &d.body {
                                DeclareOwnedVariant::CodecZenohDeclToken(_) => {
                                    assert_eq!(
                                        d.interest_id,
                                        Some(9),
                                        "DeclToken is tagged with the get's interest id"
                                    );
                                    tokens += 1;
                                }
                                DeclareOwnedVariant::CodecZenohDeclFinal(_) => {
                                    assert_eq!(
                                        d.interest_id,
                                        Some(9),
                                        "DeclFinal terminates the get's interest id"
                                    );
                                    finals += 1;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(tokens, 1, "exactly one DeclToken reply reached the group");
        assert_eq!(
            finals, 1,
            "exactly one DeclFinal terminated the interest-response chain"
        );
    }

    /// A Frame from an address that never JOINed is dropped before payload
    /// decode (zenoh-pico "Dropping _Z_FRAME from unknown peer").
    #[cfg(all(feature = "codec-push", feature = "pubsub-put"))]
    #[tokio::test]
    async fn drive_loop_drops_frame_from_unknown_peer() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use wz_session_core::frame_encode::encode_frame_with_push;
        use wz_session_core::observer::ApplicationLayerObserver;
        use wz_session_core::push_build::build_push_literal;

        let push = build_push_literal("demo/mc", b"orphan").expect("push fixture");
        let frame = encode_frame_with_push(0, push, true);
        let mut driver = FakeDriver::with([(frame, src(7))]); // no prior JOIN
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let fired = Arc::new(AtomicUsize::new(0));
        let mut observer = ApplicationLayerObserver::new();
        {
            let fired = fired.clone();
            observer.subscribers.register("demo/mc", move |_| {
                fired.fetch_add(1, Ordering::SeqCst);
            });
        }

        drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                tick_ms: 5,
                max_iters: Some(5),
            },
            &mut driver,
            &clock,
            |event| observer.dispatch_event(event),
            &mut idle_outbound(),
        )
        .await;

        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "unattributed frame must drop"
        );
    }

    // ── A1c — TX half: queued publish -> minted SN -> framed multicast ──

    /// A queued `MulticastTxItem::Push` leaves the loop as a `T_MID_FRAME`
    /// whose minted SN matches the JOIN-advertised baseline (0), whose
    /// payload round-trips back to the Push, and whose emission advances
    /// the advertised `next_sn` in subsequent JOIN beacons — on the
    /// RELIABLE channel (`multicast_put_literal` mirrors pico's
    /// `Z_RELIABILITY_DEFAULT = RELIABLE` put default).
    #[cfg(feature = "codec-push")]
    #[tokio::test]
    async fn drive_loop_frames_queued_push_and_advances_join_next_sn() {
        use wz_session_core::network_message::NetworkMessage;

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tx.send(multicast_put_literal("demo/mc", b"tx-half").expect("put item"))
            .expect("queue publish");
        drop(tx); // after the publish drains, the TX arm disarms

        let mut driver = FakeDriver::with([]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let outcome = drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                tick_ms: 5,
                max_iters: Some(8),
            },
            &mut driver,
            &clock,
            |_| {},
            &mut rx,
        )
        .await;
        assert_eq!(outcome, MulticastOutcome::IterationLimit);

        // Exactly one data frame went out, on the reliable channel
        // (R flag set — the pico put default), carrying SN 0 and the
        // Push payload.
        let frames: Vec<&Vec<u8>> = driver
            .sent
            .iter()
            .filter(|d| d[0] & 0x1f == wire_const::T_MID_FRAME)
            .collect();
        assert_eq!(frames.len(), 1, "one queued publish = one data frame");
        assert_ne!(
            frames[0][0] & wire_const::FLAG_T_FRAME_R,
            0,
            "multicast_put_literal publishes reliable (pico Z_RELIABILITY_DEFAULT)"
        );
        let parsed = parse_inbound(frames[0]).expect("frame parses");
        let InboundFrame::Frame { sn, payload, .. } = parsed else {
            panic!("expected Frame");
        };
        assert_eq!(sn, 0, "first mint on a fresh ring is 0");
        let messages = parse_frame_payload(&payload).expect("payload parses");
        assert_eq!(messages.len(), 1);
        assert!(
            matches!(&messages[0], NetworkMessage::Push(_)),
            "payload is the queued Push"
        );

        // The JOIN beacons emitted AFTER the publish advertise the
        // advanced reliable next_sn (init_rx_seq stays truthful).
        let last_join = driver
            .sent
            .iter()
            .rev()
            .find(|d| d[0] & 0x1f == wire_const::T_MID_JOIN)
            .expect("at least one JOIN beacon");
        let join = decode_join(last_join).expect("JOIN decodes");
        assert_eq!(join.next_sn_reliable, 1, "publish advanced the ring");
        assert_eq!(join.next_sn_best_effort, 0, "best-effort channel untouched");
    }

    // ── R311kn — multicast fragment RX: per-peer chains through the
    //    loop's reassembly Router ──

    #[cfg(all(feature = "reassembly", feature = "codec-push", feature = "pubsub-put"))]
    mod fragment_rx {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use wz_session_core::frame_encode::encode_frame_with_push;
        use wz_session_core::observer::ApplicationLayerObserver;
        use wz_session_core::push_build::build_push_literal;

        /// The serialized NetworkMessage batch a data frame would carry —
        /// built through the production encoders (push -> frame -> parse
        /// back the payload) so the fixture cannot drift from the wire.
        fn push_batch_bytes(keyexpr: &str, payload: &[u8]) -> Vec<u8> {
            let push = build_push_literal(keyexpr, payload).expect("push fixture");
            let frame = encode_frame_with_push(0, push, true);
            let Ok(InboundFrame::Frame { payload, .. }) = parse_inbound(&frame) else {
                panic!("frame fixture must parse");
            };
            payload
        }

        /// One reliable `T_MID_FRAGMENT` datagram: `[flags|MID]` header +
        /// the fragment body (`VLE(sn) + chunk`). `sn < 0x80` keeps the
        /// VLE single-byte (the fixtures stay in that range).
        fn fragment_dgram(sn: u8, more: bool, chunk: &[u8]) -> Vec<u8> {
            assert!(sn < 0x80, "single-byte VLE fixture range");
            let mut flags = wire_const::FLAG_T_FRAGMENT_R;
            if more {
                flags |= wire_const::FLAG_T_FRAGMENT_M;
            }
            let mut dgram = std::vec![flags | wire_const::T_MID_FRAGMENT, sn];
            dgram.extend_from_slice(chunk);
            dgram
        }

        /// A subscriber observer + fire counter for "demo/mc".
        fn counting_observer(
            expect_payload: &'static [u8],
        ) -> (ApplicationLayerObserver, Arc<AtomicUsize>) {
            let fired = Arc::new(AtomicUsize::new(0));
            let mut observer = ApplicationLayerObserver::new();
            {
                let fired = fired.clone();
                observer.subscribers.register("demo/mc", move |sample| {
                    assert_eq!(sample.payload(), expect_payload);
                    fired.fetch_add(1, Ordering::SeqCst);
                });
            }
            (observer, fired)
        }

        /// A two-fragment chain from a JOINed peer reassembles inside the
        /// drive loop and reaches the subscriber exactly once, through the
        /// SAME observer fan the whole-frame path uses (zenoh-pico
        /// `_z_multicast_handle_fragment_inner` -> defrag ->
        /// `_z_handle_network_message`).
        #[tokio::test]
        async fn drive_loop_reassembles_fragment_chain_to_subscriber() {
            let peer_b = [0x01, 0x02, 0x03, 0x04];
            let join = join0(&params(&peer_b)); // next_sn_reliable = 0
            let batch = push_batch_bytes("demo/mc", b"frag-over-multicast");
            let (head, tail) = batch.split_at(batch.len() / 2);

            let mut driver = FakeDriver::with([
                (join, src(2)),
                (fragment_dgram(0, true, head), src(2)),
                (fragment_dgram(1, false, tail), src(2)),
            ]);
            let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
            let clock = TokioTime::new();
            let (mut observer, fired) = counting_observer(b"frag-over-multicast");

            let outcome = drive_multicast_session(
                &mut dispatcher,
                MulticastDriveConfig {
                    params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                    tick_ms: 5,
                    max_iters: Some(8),
                },
                &mut driver,
                &clock,
                |event| observer.dispatch_event(event),
                &mut idle_outbound(),
            )
            .await;

            assert_eq!(outcome, MulticastOutcome::IterationLimit);
            assert_eq!(
                fired.load(Ordering::SeqCst),
                1,
                "the reassembled Push must reach the subscriber exactly once"
            );
        }

        /// A fragment chain from an address that never JOINed is dropped
        /// before any chain opens (pico "Dropping Z_FRAGMENT from unknown
        /// peer").
        #[tokio::test]
        async fn drive_loop_drops_fragments_from_unknown_peer() {
            let batch = push_batch_bytes("demo/mc", b"orphan");
            let (head, tail) = batch.split_at(batch.len() / 2);
            let mut driver = FakeDriver::with([
                (fragment_dgram(0, true, head), src(7)), // no prior JOIN
                (fragment_dgram(1, false, tail), src(7)),
            ]);
            let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
            let clock = TokioTime::new();
            let (mut observer, fired) = counting_observer(b"orphan");

            drive_multicast_session(
                &mut dispatcher,
                MulticastDriveConfig {
                    params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                    tick_ms: 5,
                    max_iters: Some(6),
                },
                &mut driver,
                &clock,
                |event| observer.dispatch_event(event),
                &mut idle_outbound(),
            )
            .await;

            assert_eq!(
                fired.load(Ordering::SeqCst),
                0,
                "unattributed chain must drop"
            );
        }

        /// An out-of-order FRAME between two fragments clears the open
        /// chain (pico clears the channel dbuf on a frame SN-gate reject),
        /// so the chain's tail can no longer complete it.
        #[tokio::test]
        async fn drive_loop_frame_ooo_aborts_open_chain() {
            let peer_b = [0x01, 0x02, 0x03, 0x04];
            let join = join0(&params(&peer_b)); // next_sn_reliable = 0
            let batch = push_batch_bytes("demo/mc", b"never-delivered");
            let (head, tail) = batch.split_at(batch.len() / 2);
            // A stale whole frame (replaying SN 0, which the first fragment
            // already consumed) — rejected by the frame gate, clearing the
            // chain head staged at SN 0.
            let stale_frame = encode_frame_with_push(
                0,
                build_push_literal("demo/mc", b"stale").expect("push fixture"),
                true,
            );

            let mut driver = FakeDriver::with([
                (join, src(2)),
                (fragment_dgram(0, true, head), src(2)),
                (stale_frame, src(2)),
                (fragment_dgram(1, false, tail), src(2)),
            ]);
            let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
            let clock = TokioTime::new();
            let (mut observer, fired) = counting_observer(b"never-delivered");

            drive_multicast_session(
                &mut dispatcher,
                MulticastDriveConfig {
                    params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                    tick_ms: 5,
                    max_iters: Some(10),
                },
                &mut driver,
                &clock,
                |event| observer.dispatch_event(event),
                &mut idle_outbound(),
            )
            .await;

            assert_eq!(
                fired.load(Ordering::SeqCst),
                0,
                "a frame SN-gate reject must clear the channel's open chain"
            );
        }

        /// A peer's Close aborts its open chain BEFORE the slot recycles:
        /// a new peer admitted into the SAME slot starts its chains clean
        /// (no generation mixing across the recycled chain key).
        #[tokio::test]
        async fn drive_loop_close_aborts_chain_before_slot_reuse() {
            let peer_b = [0x01, 0x02, 0x03, 0x04];
            let peer_c = [0x05, 0x06, 0x07, 0x08];
            let batch = push_batch_bytes("demo/mc", b"second-peer-clean");
            let (head, tail) = batch.split_at(batch.len() / 2);

            // Peer B (slot 0) opens a chain at SN 5..., then Closes. Peer C
            // (from another address, admitted into the recycled slot 0)
            // sends a clean 2-fragment chain at SN 0/1. Without the
            // eviction abort, B's poisoned head (SN 5) would make C's SN 0
            // continuation non-consecutive and abort C's chain instead.
            let join_b = params(&peer_b);
            let mut b_tx = TxSn::new(sn::mask_from_res(join_b.seq_num_res));
            b_tx.next_reliable = 5; // B advertises next_sn_reliable = 5
            let join_b_dgram = encode_join(&join_b, &b_tx);

            let mut driver = FakeDriver::with([
                (join_b_dgram, src(2)),
                (fragment_dgram(5, true, b"poison-head"), src(2)),
                (std::vec![wire_const::T_MID_CLOSE, 0x00], src(2)),
                (join0(&params(&peer_c)), src(3)), // recycles slot 0
                (fragment_dgram(0, true, head), src(3)),
                (fragment_dgram(1, false, tail), src(3)),
            ]);
            let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
            let clock = TokioTime::new();
            let (mut observer, fired) = counting_observer(b"second-peer-clean");

            drive_multicast_session(
                &mut dispatcher,
                MulticastDriveConfig {
                    params: &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                    tick_ms: 5,
                    max_iters: Some(12),
                },
                &mut driver,
                &clock,
                |event| observer.dispatch_event(event),
                &mut idle_outbound(),
            )
            .await;

            assert_eq!(dispatcher.active_peers(), 1, "B closed, C live");
            assert_eq!(
                fired.load(Ordering::SeqCst),
                1,
                "the recycled slot's new chain must complete cleanly"
            );
        }
    }

    // ── R311ko — multicast fragment TX: an oversize publish re-frames as
    //    a T_MID_FRAGMENT chain at the loop's outbound seam ──

    #[cfg(all(
        feature = "transport-fragmentation",
        feature = "reassembly",
        feature = "codec-push",
        feature = "pubsub-put"
    ))]
    mod fragment_tx {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use wz_session_core::observer::ApplicationLayerObserver;

        /// A group configured with a small frame budget — the owned push
        /// codec caps payloads at the bounded profile (msg_put
        /// `max-size="256"`), so "oversize" is a frame past a SMALL batch
        /// budget, exactly how the unicast fragmentation fixtures shrink
        /// the negotiated mtu rather than growing the message.
        fn small_batch_params(zid: &[u8]) -> MulticastParams {
            MulticastParams {
                batch_size: 64,
                ..params(zid)
            }
        }

        /// A payload comfortably past the 64-byte group batch budget,
        /// inside the owned-codec bound.
        fn oversize_payload() -> Vec<u8> {
            (0..200u32).map(|i| (i * 13) as u8).collect()
        }

        /// A queued oversize Push leaves the loop as a reliable
        /// `T_MID_FRAGMENT` chain — no oversize `T_MID_FRAME` reaches the
        /// wire, every datagram fits the batch budget, the chain SNs are
        /// ring-consecutive from the frame's minted SN (0 on a fresh
        /// ring), and the follow-on mints advance the JOIN-advertised
        /// `next_sn_reliable` to one past the chain (zenoh-pico
        /// `_z_transport_tx_send_fragment` parity).
        #[tokio::test]
        async fn drive_loop_publishes_oversize_put_as_fragment_chain() {
            let p = small_batch_params(&[0xAA, 0xBB, 0xCC, 0xDD]);
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            tx.send(multicast_put_literal("demo/mc", &oversize_payload()).expect("put item"))
                .expect("queue publish");
            drop(tx);

            let mut driver = FakeDriver::with([]);
            let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
            let clock = TokioTime::new();
            drive_multicast_session(
                &mut dispatcher,
                MulticastDriveConfig {
                    params: &p,
                    tick_ms: 5,
                    max_iters: Some(8),
                },
                &mut driver,
                &clock,
                |_| {},
                &mut rx,
            )
            .await;

            assert!(
                !driver
                    .sent
                    .iter()
                    .any(|d| d[0] & 0x1f == wire_const::T_MID_FRAME),
                "an oversize publish must never leave as a whole frame"
            );
            let frags: Vec<&Vec<u8>> = driver
                .sent
                .iter()
                .filter(|d| d[0] & 0x1f == wire_const::T_MID_FRAGMENT)
                .collect();
            assert!(frags.len() > 1, "200-byte put at batch 64 must fragment");
            for (i, frag) in frags.iter().enumerate() {
                assert!(
                    frag.len() <= p.batch_size as usize,
                    "fragment {i} is {} bytes, exceeds the batch budget",
                    frag.len()
                );
                let Ok(InboundFrame::Fragment {
                    reliable, sn, more, ..
                }) = parse_inbound(frag)
                else {
                    panic!("fragment {i} must parse");
                };
                assert!(reliable, "put default rides the reliable channel");
                assert_eq!(sn, i as u64, "chain SNs walk from the minted 0");
                assert_eq!(more, i + 1 < frags.len(), "M on all but the last");
            }

            // The JOIN beacons emitted AFTER the chain advertise the
            // post-chain next_sn (the chain consumed count SNs total).
            let last_join = driver
                .sent
                .iter()
                .rev()
                .find(|d| d[0] & 0x1f == wire_const::T_MID_JOIN)
                .expect("at least one JOIN beacon");
            let join = decode_join(last_join).expect("JOIN decodes");
            assert_eq!(
                join.next_sn_reliable,
                frags.len() as u64,
                "the chain consumed count SNs"
            );
        }

        /// TX -> RX round-trip through the production bytes: node A's
        /// drive loop publishes an oversize put, and node B's drive loop —
        /// fed A's emitted datagrams verbatim (JOIN beacons + fragment
        /// chain) — admits A, reassembles the chain, and fans the put to
        /// a registered subscriber exactly once.
        #[tokio::test]
        async fn drive_loop_oversize_put_round_trips_through_peer_loop() {
            let payload = oversize_payload();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            tx.send(multicast_put_literal("demo/mc", &payload).expect("put item"))
                .expect("queue publish");
            drop(tx);

            let mut driver_a = FakeDriver::with([]);
            let mut dispatcher_a = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
            let clock = TokioTime::new();
            drive_multicast_session(
                &mut dispatcher_a,
                MulticastDriveConfig {
                    params: &small_batch_params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                    tick_ms: 5,
                    max_iters: Some(8),
                },
                &mut driver_a,
                &clock,
                |_| {},
                &mut rx,
            )
            .await;

            // Node B ingests A's wire output in emit order.
            let inbound: Vec<(Vec<u8>, SocketAddr)> =
                driver_a.sent.iter().map(|d| (d.clone(), src(7))).collect();
            let budget = inbound.len() + 6;
            let mut driver_b = FakeDriver::with(inbound);
            let mut dispatcher_b = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));

            let fired = Arc::new(AtomicUsize::new(0));
            let mut observer = ApplicationLayerObserver::new();
            {
                let fired = fired.clone();
                let expect = payload.clone();
                observer.subscribers.register("demo/mc", move |sample| {
                    assert_eq!(sample.payload(), &expect[..]);
                    fired.fetch_add(1, Ordering::SeqCst);
                });
            }

            drive_multicast_session(
                &mut dispatcher_b,
                MulticastDriveConfig {
                    params: &small_batch_params(&[0x55, 0x66, 0x77, 0x88]),
                    tick_ms: 5,
                    max_iters: Some(budget),
                },
                &mut driver_b,
                &clock,
                |event| observer.dispatch_event(event),
                &mut idle_outbound(),
            )
            .await;

            assert_eq!(dispatcher_b.active_peers(), 1, "B admitted A's JOIN");
            assert_eq!(
                fired.load(Ordering::SeqCst),
                1,
                "the reassembled oversize put reaches the subscriber once"
            );
        }
    }

    /// Our own JOIN echoed back by multicast loopback does NOT admit us as a
    /// peer — a node is not its own peer (own-zid filter).
    #[tokio::test]
    async fn drive_loop_filters_own_join_echo() {
        let self_zid = [0xAA, 0xBB, 0xCC, 0xDD];
        // The inbound JOIN carries OUR zid (the loopback echo of our beacon).
        let mut driver = FakeDriver::with([(join0(&params(&self_zid)), src(9))]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let outcome = drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params(&self_zid),
                tick_ms: 5,
                max_iters: Some(5),
            },
            &mut driver,
            &clock,
            |_| {},
            &mut idle_outbound(),
        )
        .await;

        assert_eq!(outcome, MulticastOutcome::IterationLimit);
        assert_eq!(dispatcher.active_peers(), 0, "own JOIN must not self-admit");
    }
}

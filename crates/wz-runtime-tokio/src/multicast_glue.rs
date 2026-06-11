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

use wz_codecs::wire_const;
#[cfg(feature = "reassembly")]
use wz_session_core::drive::sweep_reporting;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
// R311lq/R311lr — `multicast_frame_or_fragments` is the codec-agnostic
// egress splitter shared by every data emit (Push, queryable Response, or
// the R311lr liveliness Declare reply), so it is gated on the union of the
// emit paths that can ride the loop, not Push alone.
#[cfg(feature = "codec-push")]
use wz_session_core::frame_encode::encode_frame_with_push;
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "liveliness-token"
))]
use wz_session_core::frame_encode::multicast_frame_or_fragments;
// R311lq — queryable reply egress over multicast: the same Frame encoders
// the unicast `SessionLinkActions::send_response{,_final}` use, sent on the
// multicast group instead of a per-peer writer channel.
#[cfg(feature = "codec-response")]
use wz_session_core::frame_encode::encode_frame_with_response;
#[cfg(feature = "codec-response-final")]
use wz_session_core::frame_encode::encode_frame_with_response_final;
// R311lr — declarer-side liveliness interest-response egress over multicast:
// the borrowed reply builders + Frame encoder the unicast
// `SessionLinkActions: DeclareReplySink` uses, multicast to the group instead
// of a per-peer writer. Gated on `liveliness-token` (the sole producer; it
// implies `declare-token` -> `codec-declare`, so the encoder is in scope).
#[cfg(feature = "liveliness-token")]
use wz_codecs::declare::DeclareOwned;
#[cfg(feature = "liveliness-token")]
use wz_session_core::declare::local_token::{build_final_reply, build_token_reply};
#[cfg(feature = "liveliness-token")]
use wz_session_core::frame_encode::encode_frame_with_declare;
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_core::link::{LinkEvent, LostCause, TxFrame};
#[cfg(feature = "reassembly")]
use wz_session_core::multicast_dispatch::{
    abort_peer_chains, ingest_multicast_fragment, multicast_chain_key,
};
use wz_session_core::multicast_dispatch::{FrameIngest, MulticastDispatcher};
use wz_session_core::multicast_join::{decode_join, encode_join, validate_join};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::network_message::parse_frame_payload;
#[cfg(feature = "codec-push")]
use wz_session_core::push_build;
use wz_session_core::reliability::Reliability;
#[cfg(feature = "codec-response-final")]
use wz_session_core::response_final_build::build_response_final;
use wz_session_core::session_fsm_multicast::SessionFsmMulticastState;
use wz_session_core::sn::{self, TxSn};

use wz_runtime_core::TimeSource;

use crate::LinkDriver;

/// One queued outbound data emission for the multicast drive loop's TX
/// half (A1c). The application side holds the paired
/// `tokio::sync::mpsc::UnboundedSender` and enqueues items; the loop
/// mints the channel SN, wraps the network message in a `T_MID_FRAME` —
/// re-framed as a `T_MID_FRAGMENT` chain when it exceeds the group batch
/// budget (R311ko,
/// [`multicast_frame_or_fragments`](wz_session_core::frame_encode::multicast_frame_or_fragments))
/// — and multicasts it to the group: the multicast mirror of the unicast
/// writer-channel seam
/// (zenoh-pico `_z_send_n_msg` over the multicast transport). The enum is
/// unconditional (signature stability); the variants are gated by the
/// codec that encodes them, so a build without any data codec carries an
/// uninhabited type and a dead arm-free match.
#[derive(Debug)]
pub enum MulticastTxItem {
    /// A pub/sub Push (`z_put` / `z_del` over multicast). Framed via the
    /// [`encode_frame_with_push`] SSOT with a freshly minted channel SN.
    #[cfg(feature = "codec-push")]
    Push {
        /// The built Push network message
        /// ([`push_build::build_push_literal`] and friends).
        push: wz_codecs::push::PushOwned,
        /// Channel selection: reliable mints on the reliable ring,
        /// best-effort on the other (multicast UDP delivery is
        /// best-effort either way; the flag governs the SN channel +
        /// the frame's R flag).
        reliable: bool,
    },
    /// R311lq — a queryable `Response(Reply|Err)` over multicast: the
    /// reply a queryable's handler produced for a Query that arrived on
    /// the group. Staged by the observer during `dispatch_event` and
    /// drained through [`MulticastReplySink`] onto this channel; the
    /// loop frames it via the [`encode_frame_with_response`] SSOT and
    /// multicasts it (reliable — zenoh-pico replies on the multicast
    /// transport through the same `_z_send_n_msg` path with
    /// `Z_RELIABILITY_RELIABLE`). The querier on the group matches it to
    /// its pending Query by request id.
    #[cfg(feature = "codec-response")]
    Response {
        /// The built `Response` network message (drained from the
        /// observer's `pending_replies` via `QueryReply::into_response`).
        response: wz_codecs::response::ResponseOwned,
    },
    /// R311lq — the `ResponseFinal` terminating a multicast reply chain
    /// for `request_id`. Unconditionally reliable: dropping it would leave
    /// the querier's `z_get` waiting for a terminal that never re-emits.
    /// Built from the rid via [`build_response_final`] and framed via
    /// [`encode_frame_with_response_final`].
    #[cfg(feature = "codec-response-final")]
    ResponseFinal {
        /// The request id whose reply chain this frame terminates (drained
        /// from the observer's `pending_final_rids`).
        request_id: u64,
    },
    /// R311lr — a declarer-side liveliness interest-response
    /// `Declare(DeclToken|DeclFinal)` over multicast: the reply a held
    /// liveliness token produced for an `Interest` (CURRENT) that arrived on
    /// the group. Staged by the observer during `dispatch_event` and drained
    /// through [`MulticastReplySink`]'s
    /// [`DeclareReplySink`](wz_session_core::response_sink::DeclareReplySink)
    /// impl onto this channel; the loop frames it via the
    /// [`encode_frame_with_declare`] SSOT and multicasts it (reliable —
    /// zenoh-pico's `_z_send_declare` rides `_z_send_n_msg` with
    /// `Z_RELIABILITY_RELIABLE`, src/net/primitives.c:52, which dispatches to
    /// the multicast transport when the session is multicast). The querier on
    /// the group matches it to its pending liveliness Interest by
    /// `interest_id`. Carries the owned `DeclareOwned` because the
    /// borrowed-arg sink seam resolves the keyexpr at drain (mirror of the
    /// unicast `SessionLinkActions: DeclareReplySink`, which routes the same
    /// owned form through its inherent `send_declare`).
    #[cfg(feature = "liveliness-token")]
    DeclareReply {
        /// The built `Declare` reply (a `DeclToken` for a held token, or the
        /// terminating `DeclFinal`), already owned via `Declare::try_into_owned`.
        declare: DeclareOwned,
    },
}

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

/// Convenience builder: a literal-keyexpr Put as a queued
/// [`MulticastTxItem`] on the RELIABLE channel — zenoh's put default
/// (zenoh-pico `Z_RELIABILITY_DEFAULT = Z_RELIABILITY_RELIABLE`,
/// api/constants.h:203, multicast included; the reliable channel has no
/// retransmit on either implementation — pico rx.c "only monotonic SNs
/// are ensured" — so the flag selects the SN ring + frame R flag, not a
/// delivery guarantee). Composes [`push_build::build_push_literal`];
/// richer pushes (Del / best-effort / aliased keyexpr / metadata)
/// construct the item directly.
#[cfg(feature = "codec-push")]
pub fn multicast_put_literal(
    keyexpr_suffix: &str,
    payload: &[u8],
) -> Result<MulticastTxItem, sce_forge_runtime::codec::CodecError> {
    Ok(MulticastTxItem::Push {
        push: push_build::build_push_literal(keyexpr_suffix, payload)?,
        reliable: true,
    })
}

/// Outcome of one [`drive_multicast_session`] run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MulticastOutcome {
    /// The session left Running (e.g. a pre-stopped dispatcher).
    Stopped,
    /// The multicast link was lost.
    LinkLost(LostCause),
    /// The bounded iteration budget was exhausted (test guard).
    IterationLimit,
}

/// Drive a multicast session: bring the link up, then own the §3.1 Running
/// concerns (periodic JOIN emit, RX classify -> dispatch + the A1b data
/// plane, lease sweep) until the link is lost or `max_iters` is reached.
///
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
    params: &MulticastParams,
    driver: &mut D,
    clock: &T,
    max_iters: Option<usize>,
    tick_ms: u64,
    mut on_event: F,
    outbound: &mut UnboundedReceiver<MulticastTxItem>,
) -> MulticastOutcome
where
    D: LinkDriver,
    T: TimeSource,
    F: FnMut(IterationEvent<'_>),
{
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
                Some(item) => match item {
                    #[cfg(feature = "codec-push")]
                    MulticastTxItem::Push { push, reliable } => {
                        // TxData: mint the channel SN, wrap in a
                        // T_MID_FRAME (frame_encode SSOT), multicast to
                        // the group. R311ko — a frame past the group
                        // batch budget re-frames as a T_MID_FRAGMENT
                        // chain riding the same minted SN
                        // (multicast_frame_or_fragments, zenoh-pico
                        // common-TX parity). Send failure is non-fatal
                        // like the JOIN beacon (UDP multicast is
                        // best-effort; the SN gap a dropped datagram
                        // leaves stays inside receivers' half-window —
                        // though a hole in a fragment chain aborts that
                        // chain at every receiver, as on pico).
                        let frame_sn = tx_sn.mint(reliable);
                        let dgram = encode_frame_with_push(frame_sn, push, reliable);
                        let reliability = if reliable {
                            Reliability::Reliable
                        } else {
                            Reliability::BestEffort
                        };
                        for dgram in multicast_frame_or_fragments(
                            dgram,
                            frame_sn,
                            reliable,
                            params.batch_size as usize,
                            &mut tx_sn,
                        ) {
                            let frame = TxFrame { bytes: &dgram };
                            let _ = driver.send(&frame, reliability).await;
                        }
                    }
                    // R311lq — queryable reply egress: a Query that arrived on
                    // the group was dispatched to a queryable whose handler
                    // staged a reply; the observer drained it through
                    // `MulticastReplySink` onto this channel. Reliable like
                    // a reliable-ring put (zenoh-pico replies via the same
                    // `_z_send_n_msg` multicast TX with `Z_RELIABILITY_RELIABLE`,
                    // src/net/primitives.c `_z_send_reply`); a large reply
                    // re-frames as a `T_MID_FRAGMENT` chain exactly like an
                    // oversize Push. Send failure is non-fatal (a dropped reply
                    // hangs that one querier's `z_get` until its timeout, as a
                    // lost unicast reply would).
                    #[cfg(feature = "codec-response")]
                    MulticastTxItem::Response { response } => {
                        let frame_sn = tx_sn.mint(/* reliable = */ true);
                        let dgram =
                            encode_frame_with_response(frame_sn, response, /* reliable = */ true);
                        for dgram in multicast_frame_or_fragments(
                            dgram,
                            frame_sn,
                            true,
                            params.batch_size as usize,
                            &mut tx_sn,
                        ) {
                            let frame = TxFrame { bytes: &dgram };
                            let _ = driver.send(&frame, Reliability::Reliable).await;
                        }
                    }
                    // R311lq — the terminal of a multicast reply chain. Always
                    // reliable and always tiny (a single VLE rid), so it never
                    // reaches the fragment budget: one minted reliable-ring SN,
                    // one frame, one send. Mirrors the unicast
                    // `send_response_final` (reliability pinned).
                    #[cfg(feature = "codec-response-final")]
                    MulticastTxItem::ResponseFinal { request_id } => {
                        let frame_sn = tx_sn.mint(/* reliable = */ true);
                        let dgram = encode_frame_with_response_final(
                            frame_sn,
                            build_response_final(request_id),
                            /* reliable = */ true,
                        );
                        let frame = TxFrame { bytes: &dgram };
                        let _ = driver.send(&frame, Reliability::Reliable).await;
                    }
                    // R311lr — declarer-side liveliness interest-response
                    // egress: an `Interest` (CURRENT) that arrived on the group
                    // matched a held liveliness token whose `Declare(DeclToken)`
                    // + terminating `DeclFinal` reply the observer staged; the
                    // closure drained it through `MulticastReplySink`'s
                    // `DeclareReplySink` impl onto this channel. Reliable —
                    // zenoh-pico's `_z_send_declare` rides `_z_send_n_msg` with
                    // `Z_RELIABILITY_RELIABLE` (src/net/primitives.c:52), which
                    // dispatches to the multicast transport for a multicast
                    // session; a large held-token keyexpr re-frames as a
                    // `T_MID_FRAGMENT` chain exactly like an oversize Push /
                    // Response. Send failure is non-fatal (a dropped reply leaves
                    // that one querier's liveliness Interest unanswered until its
                    // timeout, as a lost unicast Declare would).
                    #[cfg(feature = "liveliness-token")]
                    MulticastTxItem::DeclareReply { declare } => {
                        let frame_sn = tx_sn.mint(/* reliable = */ true);
                        let dgram =
                            encode_frame_with_declare(frame_sn, declare, /* reliable = */ true);
                        for dgram in multicast_frame_or_fragments(
                            dgram,
                            frame_sn,
                            true,
                            params.batch_size as usize,
                            &mut tx_sn,
                        ) {
                            let frame = TxFrame { bytes: &dgram };
                            let _ = driver.send(&frame, Reliability::Reliable).await;
                        }
                    }
                },
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
                        match rx.bytes.first().map(|h| h & 0x1f) {
                            Some(wire_const::T_MID_JOIN) => {
                                // A JOIN announces its zid; validate (§3.2
                                // rejection rules), then admit / refresh the
                                // peer at this address and seed its RX SN
                                // baselines. Filter our own zid: with
                                // multicast loopback on our beacon echoes
                                // back, and a node is not its own peer.
                                if let Some(join) = decode_join(&rx.bytes) {
                                    if join.zid != params.zid.as_slice() {
                                        if let Some(baseline) =
                                            validate_join(&join, params)
                                        {
                                            dispatcher.ingest_join(
                                                join.zid, src, baseline, now,
                                            );
                                        }
                                    }
                                }
                            }
                            Some(wire_const::T_MID_FRAME) => {
                                // A1b data plane: decode the Frame envelope,
                                // admit it against the sender's per-channel SN
                                // gate (which also refreshes its lease), and
                                // fan the NetworkMessage batch to the observer
                                // callback. A frame from an unknown peer, an
                                // out-of-order SN, or a malformed envelope /
                                // payload is dropped — pico logs and moves on;
                                // one bad datagram must not stop the group.
                                if let Ok(InboundFrame::Frame {
                                    reliable,
                                    sn,
                                    payload,
                                    has_ext,
                                    extensions,
                                }) = parse_inbound(&rx.bytes)
                                {
                                    match dispatcher.ingest_frame_by_src(src, reliable, sn, now) {
                                        FrameIngest::Admitted => {
                                            if let Ok(messages) = parse_frame_payload(&payload)
                                            {
                                                let outcome = DriverLoopOutcome::FramePayload {
                                                    reliable,
                                                    sn,
                                                    messages,
                                                    has_ext,
                                                    extensions,
                                                };
                                                on_event(IterationEvent::Poll(&outcome));
                                            }
                                        }
                                        // R311kn — an out-of-order FRAME clears
                                        // the channel's in-progress reassembly
                                        // chain (pico clears the dbuf + state,
                                        // multicast/rx.c
                                        // `_z_multicast_handle_frame`): the
                                        // dropped frame may have superseded the
                                        // chain's continuation, so completing it
                                        // would mix generations.
                                        #[cfg(feature = "reassembly")]
                                        FrameIngest::OutOfOrder => {
                                            if let Some(idx) =
                                                dispatcher.peer_index_by_src(src)
                                            {
                                                reasm.abort_channel(
                                                    &multicast_chain_key(idx),
                                                    reliable,
                                                );
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // R311kn — the multicast fragment RX arm: SN-gate
                            // per peer, reassemble per (slot, channel) chain,
                            // and fan the completed message through the SAME
                            // observer event the Frame arm uses (zenoh-pico
                            // `_z_multicast_handle_fragment_inner`). Without
                            // `reassembly` the MID falls to the `_` arm and
                            // the fragment is dropped — pico "Fragment dropped
                            // because fragmentation feature is deactivated".
                            #[cfg(feature = "reassembly")]
                            Some(wire_const::T_MID_FRAGMENT) => {
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
                            Some(wire_const::T_MID_KEEP_ALIVE) => {
                                // A liveness ping refreshes the sender's lease
                                // (robustness if its JOINs are lost).
                                dispatcher.refresh_by_src(src, now);
                            }
                            Some(wire_const::T_MID_CLOSE) => {
                                // Graceful departure (the Close carries no zid,
                                // so it is attributed by source address).
                                // R311kn — the departing peer's in-progress
                                // chains die with it (pico's per-entry dbufs),
                                // BEFORE the slot index can be re-issued.
                                #[cfg(feature = "reassembly")]
                                if let Some(idx) = dispatcher.peer_index_by_src(src) {
                                    abort_peer_chains(&mut reasm, idx);
                                }
                                dispatcher.close_by_src(src);
                            }
                            _ => {}
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

    use wz_session_core::link::RxFrame;
    use wz_session_core::multicast_dispatch::MulticastConfig;
    use wz_session_core::multicast_peer::MulticastPeerState;

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
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]), // self
            &mut driver,
            &clock,
            Some(5),
            5,
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
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
            &mut driver,
            &clock,
            Some(8),
            5,
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
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
            &mut driver,
            &clock,
            Some(5),
            5,
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
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
            &mut driver,
            &clock,
            Some(5),
            5,
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
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
            &mut driver,
            &clock,
            Some(5),
            5,
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
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
            &mut driver,
            &clock,
            Some(8),
            5,
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
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
            &mut driver,
            &clock,
            Some(12),
            5,
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
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
            &mut driver,
            &clock,
            Some(12),
            5,
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
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
            &mut driver,
            &clock,
            Some(5),
            5,
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
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
            &mut driver,
            &clock,
            Some(8),
            5,
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
                &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                &mut driver,
                &clock,
                Some(8),
                5,
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
                &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                &mut driver,
                &clock,
                Some(6),
                5,
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
                &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                &mut driver,
                &clock,
                Some(10),
                5,
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
                &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                &mut driver,
                &clock,
                Some(12),
                5,
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
                &p,
                &mut driver,
                &clock,
                Some(8),
                5,
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
                &small_batch_params(&[0xAA, 0xBB, 0xCC, 0xDD]),
                &mut driver_a,
                &clock,
                Some(8),
                5,
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
                &small_batch_params(&[0x55, 0x66, 0x77, 0x88]),
                &mut driver_b,
                &clock,
                Some(budget),
                5,
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
            &params(&self_zid),
            &mut driver,
            &clock,
            Some(5),
            5,
            |_| {},
            &mut idle_outbound(),
        )
        .await;

        assert_eq!(outcome, MulticastOutcome::IterationLimit);
        assert_eq!(dispatcher.active_peers(), 0, "own JOIN must not self-admit");
    }
}

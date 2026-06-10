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
//! realises them:
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

use sce_forge_runtime::codec::SceCursor;

use tokio::sync::mpsc::UnboundedReceiver;

use wz_codecs::join::Join;
use wz_codecs::wire_const;
#[cfg(feature = "reassembly")]
use wz_session_core::drive::sweep_reporting;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
#[cfg(feature = "codec-push")]
use wz_session_core::frame_encode::{encode_frame_with_push, multicast_frame_or_fragments};
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_core::link::{LinkEvent, LostCause, TxFrame};
#[cfg(feature = "reassembly")]
use wz_session_core::multicast_dispatch::{
    abort_peer_chains, ingest_multicast_fragment, multicast_chain_key,
};
use wz_session_core::multicast_dispatch::{FrameIngest, JoinBaseline, MulticastDispatcher};
use wz_session_core::multicast_params::{
    pack_res_cbyte, unpack_res_cbyte, MulticastParams, PROTOCOL_DEFAULT_BATCH_SIZE,
    PROTOCOL_DEFAULT_RESOLUTION,
};
use wz_session_core::network_message::parse_frame_payload;
#[cfg(feature = "codec-push")]
use wz_session_core::push_build;
use wz_session_core::reliability::Reliability;
use wz_session_core::session_fsm_multicast::SessionFsmMulticastState;
use wz_session_core::sn::{self, TxSn};

use wz_runtime_core::TimeSource;

use crate::LinkDriver;

/// Frame a multicast JOIN datagram for `params`:
/// `[T_MID_JOIN][version][cbyte][zid][S: res-cbyte + batch][lease vle]`
/// `[next_sn_r vle][next_sn_be vle]`.
///
/// R311kq — the S-flag optionals (`sn_res` resolution cbyte +
/// `batch_size`) are present exactly when the config departs from the
/// protocol defaults ([`MulticastParams::join_advertises_caps`], zenoh-pico
/// `_z_t_msg_make_join` parity): an omitted optional is the wire statement
/// "I run the protocol defaults", so a non-default config MUST advertise
/// or every protocol-default peer would mis-read its caps. The body codec
/// omits the MID byte, so header + S flag are prepended here (mirror of
/// [`crate::scouting_glue`]'s `scout_emit`).
///
/// R311kr — a whole-second lease rides the wire in SECONDS under the
/// `T` header flag ([`wire_const::FLAG_T_JOIN_T`]), pico `make_join`
/// parity (`lease % 1000 == 0` sets T, definitions/transport.c:113-115;
/// the codec then divides, codec/transport.c:59-62). The pico default
/// lease 10000ms therefore arrives as T=1 + VLE 10 — an encoder that
/// never set T was fine on its own wire (T=0 = milliseconds) but the
/// decode side MUST honor T or it mis-reads every pico beacon 1000x.
///
/// A1c — the JOIN advertises the LIVE per-channel `next_sn` from `tx_sn`
/// (the §3.2 `init_rx_seq` contract: receivers seed their RX baseline one
/// before these, so the next data frame this node mints is admitted).
pub fn encode_join(params: &MulticastParams, tx_sn: &TxSn) -> Vec<u8> {
    let zid = &params.zid;
    let mut join = Join::new();
    join.version = params.version;
    join.set_whatami(params.whatami);
    if !zid.is_empty() {
        join.set_zid_len_m1((zid.len() - 1) as u8);
        join.zid = zid.as_slice();
    }
    let advertises = params.join_advertises_caps();
    if advertises {
        join.sn_res = Some(pack_res_cbyte(params.seq_num_res, params.req_id_res));
        join.batch_size = Some(params.batch_size);
    }
    let lease_in_seconds = params.lease_ms % 1000 == 0;
    join.lease = if lease_in_seconds {
        params.lease_ms / 1000
    } else {
        params.lease_ms
    };
    join.next_sn_reliable = tx_sn.next_reliable;
    join.next_sn_best_effort = tx_sn.next_best_effort;
    let body = join.encode_to_vec(u8::from(advertises));

    let mut dgram = Vec::with_capacity(1 + body.len());
    let mut flags = if advertises {
        wire_const::FLAG_T_JOIN_S
    } else {
        0
    };
    if lease_in_seconds {
        flags |= wire_const::FLAG_T_JOIN_T;
    }
    dgram.push(flags | wire_const::T_MID_JOIN);
    dgram.extend_from_slice(&body);
    dgram
}

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

/// If `bytes` is a multicast JOIN datagram, decode its full body (a
/// borrowed view into `bytes`). Returns `None` for a non-JOIN MID or a
/// malformed body. The returned `lease` is ALWAYS milliseconds — the
/// `T` header flag's seconds form is projected back here (R311kr), so
/// consumers never see the wire unit. The caller validates the
/// announcement (§3.2 rejection rules — [`validate_join`]) before
/// feeding it to [`MulticastDispatcher::ingest_join`].
pub fn decode_join(bytes: &[u8]) -> Option<Join<'_>> {
    let header = *bytes.first()?;
    if header & 0x1f != wire_const::T_MID_JOIN {
        return None;
    }
    // The `join` codec gates its optional sn_res / batch_size on `s & 0x01`,
    // so project the wire S flag (header bit 6, `FLAG_T_JOIN_S` = 0x40, per
    // zenoh-pico transport.h:61) to that bit. A minimal JOIN clears S so
    // `s` is 0, but project from the named flag (not a raw shift) so a
    // future richer JOIN decodes correctly — header bit 5 is the distinct
    // `_Z_FLAG_T_JOIN_T` lease-unit flag (handled below), NOT S, so a
    // `header >> 5` shift would read the wrong bit.
    let s = u8::from(header & wire_const::FLAG_T_JOIN_S != 0);
    let mut cursor = SceCursor::new(&bytes[1..]);
    let mut join = Join::decode(&mut cursor, s).ok()?;
    // R311kr — T flag = the lease VLE is in SECONDS; project back to the
    // milliseconds every wz consumer speaks (pico decode parity,
    // codec/transport.c:161-164: `_lease = _lease * 1000`). The default
    // pico beacon (lease 10000ms) arrives as T=1 + VLE 10, so skipping
    // this read it as 10ms. Saturating: pico multiplies unchecked, but a
    // hostile VLE near u64::MAX must not panic the RX loop.
    if header & wire_const::FLAG_T_JOIN_T != 0 {
        join.lease = join.lease.saturating_mul(1000);
    }
    Some(join)
}

/// If `bytes` is a multicast JOIN datagram, decode it and return the
/// announcer's zid (a sub-slice borrow of `bytes`). Returns `None` for a
/// non-JOIN MID or a malformed body. Thin projection of [`decode_join`].
pub fn decode_join_zid(bytes: &[u8]) -> Option<&[u8]> {
    decode_join(bytes).map(|join| join.zid)
}

/// §3.2 rejection rules for an inbound JOIN announcement, ahead of
/// [`MulticastDispatcher::ingest_join`] (the dispatcher's documented
/// contract: "the caller has already validated the Join"). Mirrors
/// zenoh-pico's checks — version (`_z_multicast_handle_join_inner`
/// proto-version guard) and the seq-num / req-id resolution + batch-size
/// compatibility from the same pico incompatible-config guard (multicast
/// has no negotiation, so peers must already agree; R311ko batch, R311kq
/// req-id).
///
/// R311kq — omitted-optional semantics are pico's decode semantics: an
/// absent `sn_res` / `batch_size` means the PROTOCOL defaults
/// ([`PROTOCOL_DEFAULT_RESOLUTION`] / [`PROTOCOL_DEFAULT_BATCH_SIZE`],
/// codec/transport.c:155-157), NOT this node's local config — a
/// non-default announcer advertises (S=1). The advertised resolution
/// cbyte packs `seq_num_res` (bits 0-1) + `req_id_res` (bits 2-3); the
/// codec carries it opaque, so it is decomposed here
/// ([`unpack_res_cbyte`]) — comparing the whole byte against the 2-bit
/// `seq_num_res` would refuse every compatible S=1 announcer.
/// Returns the admitted baselines (per-channel SN + the announcer's
/// advertised lease, both stored per peer by
/// [`MulticastDispatcher::ingest_join`] — R311ks), or `None` when the
/// announcement must be ignored (a diagnostic event, not a peer-FSM
/// transition). The lease is NOT validated — any advertisement is
/// accepted (pico parity; the Router caps the hold window locally).
pub fn validate_join(join: &Join<'_>, params: &MulticastParams) -> Option<JoinBaseline> {
    if join.version != params.version {
        return None;
    }
    let res_cbyte = join.sn_res.unwrap_or(pack_res_cbyte(
        PROTOCOL_DEFAULT_RESOLUTION,
        PROTOCOL_DEFAULT_RESOLUTION,
    ));
    let (seq_num_res, req_id_res) = unpack_res_cbyte(res_cbyte);
    if seq_num_res != params.seq_num_res || req_id_res != params.req_id_res {
        return None;
    }
    if join.batch_size.unwrap_or(PROTOCOL_DEFAULT_BATCH_SIZE) != params.batch_size {
        return None;
    }
    Some(JoinBaseline {
        sn_res: seq_num_res,
        next_sn_reliable: join.next_sn_reliable,
        next_sn_best_effort: join.next_sn_best_effort,
        // Always milliseconds here — decode_join projected the wire
        // T-flag seconds form back before this point (R311kr).
        lease_ms: join.lease,
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

    /// A params bundle at the PROTOCOL defaults (8192 / 0x02 / 0x02) —
    /// the only config whose JOIN is minimal (S=0) under the R311kq
    /// pico `make_join` parity.
    fn protocol_default_params(zid: &[u8]) -> MulticastParams {
        MulticastParams {
            batch_size: PROTOCOL_DEFAULT_BATCH_SIZE,
            ..params(zid)
        }
    }

    /// `encode_join` frames a JOIN whose MID is `T_MID_JOIN` and whose
    /// body round-trips back to the announcer zid through
    /// `decode_join_zid` (the fixture batch 2048 is non-default, so the
    /// header also carries S — masked out of the MID compare).
    #[test]
    fn encode_join_round_trips_zid() {
        let zid = [0xAA, 0xBB, 0xCC, 0xDD];
        let dgram = join0(&params(&zid));
        assert_eq!(dgram[0] & 0x1f, wire_const::T_MID_JOIN);
        assert_eq!(decode_join_zid(&dgram), Some(&zid[..]));
    }

    /// R311kq — a protocol-default config emits the minimal JOIN (S=0,
    /// no optionals): omitted IS the honest advertisement of the
    /// protocol defaults (pico `make_join` sets S only off-default).
    /// The fixture's whole-second lease (5000ms) still rides the T flag
    /// (R311kr) — T is the lease UNIT, orthogonal to the S caps.
    #[test]
    fn encode_join_is_minimal_at_protocol_defaults() {
        let p = protocol_default_params(&[0x01, 0x02, 0x03, 0x04]);
        let dgram = join0(&p);
        assert_eq!(dgram[0] & wire_const::FLAG_T_JOIN_S, 0, "no S flag");
        assert_eq!(
            dgram[0] & !(wire_const::FLAG_T_JOIN_S | wire_const::FLAG_T_JOIN_T),
            wire_const::T_MID_JOIN
        );
        let join = decode_join(&dgram).expect("JOIN decodes");
        assert_eq!(join.sn_res, None);
        assert_eq!(join.batch_size, None);
        assert!(
            validate_join(&join, &p).is_some(),
            "protocol-default group admits the minimal JOIN"
        );
    }

    /// R311kq — a non-default config (batch 2048) advertises S=1 with
    /// the packed resolution cbyte (seq 0x02 | req 0x02 << 2 = 0x0A) +
    /// batch, and a same-config group admits it through the cbyte
    /// decomposition (the pre-R311kq whole-byte compare refused every
    /// compatible S=1 announcer).
    #[test]
    fn encode_join_advertises_non_default_caps() {
        let zid = [0x01, 0x02, 0x03, 0x04];
        let p = params(&zid);
        let dgram = join0(&p);
        assert_ne!(dgram[0] & wire_const::FLAG_T_JOIN_S, 0, "S flag set");
        let join = decode_join(&dgram).expect("JOIN decodes");
        assert_eq!(join.sn_res, Some(0x0A), "seq 2 | req 2 << 2");
        assert_eq!(join.batch_size, Some(2_048));
        assert!(
            validate_join(&join, &p).is_some(),
            "same-config group admits the advertised caps"
        );
    }

    /// R311kr — pico `make_join` lease-unit parity: a whole-second lease
    /// sets the T header flag and rides the wire in SECONDS (the pico
    /// default 10000ms beacon is T=1 + a one-byte VLE 10); `decode_join`
    /// projects it back so consumers always see milliseconds. The
    /// pre-R311kr decoder ignored T and read that beacon as 10ms.
    #[test]
    fn encode_join_whole_second_lease_rides_t_flag() {
        let mut p = protocol_default_params(&[0x01, 0x02, 0x03, 0x04]);
        p.lease_ms = 10_000;
        let dgram = join0(&p);
        assert_ne!(dgram[0] & wire_const::FLAG_T_JOIN_T, 0, "T flag set");
        // header(1) + version(1) + cbyte(1) + zid(4) -> lease VLE at 7;
        // 10 fits one VLE byte, so the raw wire value is visible here.
        assert_eq!(dgram[7], 10, "wire VLE carries seconds");
        let join = decode_join(&dgram).expect("JOIN decodes");
        assert_eq!(join.lease, 10_000, "lease projected back to ms");
    }

    /// R311kr — a sub-second-granularity lease cannot ride the seconds
    /// form: T stays clear and the lease VLE carries raw milliseconds
    /// (pico `make_join` sets T only when `lease % 1000 == 0`).
    #[test]
    fn encode_join_fractional_lease_stays_in_ms() {
        let mut p = protocol_default_params(&[0x01, 0x02, 0x03, 0x04]);
        p.lease_ms = 1_500;
        let dgram = join0(&p);
        assert_eq!(dgram[0] & wire_const::FLAG_T_JOIN_T, 0, "T flag clear");
        let join = decode_join(&dgram).expect("JOIN decodes");
        assert_eq!(join.lease, 1_500);
    }

    /// R311ks — the wire-advertised lease flows through `validate_join`
    /// into the admitted baseline (zenoh-pico `entry->_lease =
    /// msg->_lease`, multicast/rx.c:393), already projected to ms by
    /// `decode_join` (the 7s lease rides the T-flag seconds form).
    #[test]
    fn validate_join_passes_advertised_lease() {
        let mut p = protocol_default_params(&[0x01, 0x02, 0x03, 0x04]);
        p.lease_ms = 7_000;
        let dgram = join0(&p);
        let join = decode_join(&dgram).expect("JOIN decodes");
        let baseline = validate_join(&join, &p).expect("admitted");
        assert_eq!(baseline.lease_ms, 7_000);
    }

    /// R311kq — pico omitted-optional semantics: a minimal JOIN means
    /// the PROTOCOL defaults, so a non-default group (batch 2048) must
    /// refuse it (`_z_multicast_handle_join_inner` compares the decoded
    /// default 8192 against the local config).
    #[test]
    fn validate_join_rejects_minimal_join_in_non_default_group() {
        let zid = [0x01, 0x02, 0x03, 0x04];
        let minimal = join0(&protocol_default_params(&zid));
        let join = decode_join(&minimal).expect("JOIN decodes");
        assert!(
            validate_join(&join, &params(&zid)).is_none(),
            "omitted batch means 8192, not the local 2048"
        );
    }

    /// R311kq — the req-id bits of the resolution cbyte are checked too:
    /// seq matches (0x02) but req differs (0x01) -> refused (pico checks
    /// `_req_id_res != Z_REQ_RESOLUTION` in the same guard).
    #[test]
    fn validate_join_rejects_mismatched_req_id_res() {
        use wz_codecs::join::Join;
        let p = params(&[0x01, 0x02, 0x03, 0x04]);
        let mut join = Join::new();
        join.version = p.version;
        join.set_whatami(p.whatami);
        join.set_zid_len_m1(3);
        join.zid = &[0x05, 0x06, 0x07, 0x08];
        join.sn_res = Some(pack_res_cbyte(0x02, 0x01)); // seq ok, req off
        join.batch_size = Some(p.batch_size);
        join.lease = p.lease_ms;
        assert!(validate_join(&join, &p).is_none(), "req-id mismatch");
    }

    /// `decode_join_zid` rejects a datagram whose MID is not `T_MID_JOIN`.
    #[test]
    fn decode_rejects_non_join_mid() {
        // A T_MID_KEEP_ALIVE (0x04) datagram, not a JOIN.
        let dgram = [wire_const::T_MID_KEEP_ALIVE, 0x00];
        assert_eq!(decode_join_zid(&dgram), None);
        assert_eq!(decode_join_zid(&[]), None);
    }

    /// A richer JOIN with the S flag set (sn_res + batch_size present) still
    /// yields the announcer zid: the `s`-flag projection reads bit 6
    /// (`FLAG_T_JOIN_S`), so the optional fields stay aligned and the body
    /// decodes whole.
    #[test]
    fn decode_join_with_s_flag_extracts_zid() {
        use wz_codecs::join::Join;
        let zid = [0x11, 0x22, 0x33];
        let mut join = Join::new();
        join.version = 0x09;
        join.set_whatami(0x01);
        join.set_zid_len_m1((zid.len() - 1) as u8);
        join.zid = &zid;
        join.sn_res = Some(0x00);
        join.batch_size = Some(0xFFFF);
        join.lease = 5_000;
        let body = join.encode_to_vec(1); // s=1: sn_res + batch_size written
        let mut dgram = std::vec![wire_const::T_MID_JOIN | wire_const::FLAG_T_JOIN_S];
        dgram.extend_from_slice(&body);
        assert_eq!(decode_join_zid(&dgram), Some(&zid[..]));
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

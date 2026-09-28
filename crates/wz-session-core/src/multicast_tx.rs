// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311lx — the shared multicast TX emit SSOT.
//!
//! The §3.1 TxData decision — "given a queued outbound [`MulticastTxItem`],
//! which channel SN does it mint and which `T_MID_FRAME` (or `T_MID_FRAGMENT`
//! chain) does it become?" — lives here ONCE, consumed by BOTH the AP drive
//! loop (`wz_runtime_tokio::multicast_glue::drive_multicast_session`) and the
//! MCU drive loop (`wz_session_lwip::multicast_drive::run_multicast_session`).
//! It is the TX twin of [`crate::multicast_rx::dispatch_multicast_inbound`]:
//! the engine-free contract those loops state — every decision PRIMITIVE is the
//! shared `wz_session_core` SSOT — applied to the egress half, so the
//! item-variant -> `encode_frame_with_*` mapping is not copied per loop. The
//! loops own only the IO around it: how the next item is OBTAINED (the AP's
//! `tokio::sync::mpsc` receiver vs the MCU's per-iteration pull) and how each
//! returned datagram is physically SENT (the AP's async `LinkDriver::send` vs
//! the MCU's `send_to_group`).
//!
//! The per-variant `mint -> encode_frame_with_* -> multicast_frame_or_fragments`
//! orchestration is behaviour-identical to the inline arm the AP loop carried
//! before R311lx; only its home moved.
//!
//! R2928 — the orchestration is now `multicast_tx_push`: room is asked of a
//! bounded `MulticastTxQueue` before each SN is minted, as upstream's
//! multicast pipeline does. `multicast_tx_emit` is that push over a queue
//! that always has room, so both loops keep one producer.

// Only the boxed variants (Push / Response / DeclareReply) name Box; a build
// with only the unboxed ResponseFinal (or no data codec) must not import it.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "liveliness-token"
))]
use alloc::boxed::Box;
use alloc::vec::Vec;

// R311y227 — the per-priority multicast conduit send-side band type. R2928 —
// unconditional: every queue lane is named by it, whichever codecs are built.
use crate::qos::Priority;

use crate::link::{RoomAnswer, RoomWait};
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
use crate::{
    link::LinkRoom,
    session_init_params::TxQueueConf,
    tx_deadline::{PushDeadline, PushOutcome},
};

/// One queued outbound data emission for a multicast drive loop's TX half
/// (A1c). The application enqueues items (the AP via a
/// `tokio::sync::mpsc::UnboundedSender`, the MCU via its per-iteration pull
/// seam); the loop hands each to [`multicast_tx_emit`], which mints the channel
/// SN, wraps the network message in a `T_MID_FRAME` — re-framed as a
/// `T_MID_FRAGMENT` chain when it exceeds the group batch budget (R311ko,
/// [`multicast_frame_or_fragments`](crate::frame_encode::multicast_frame_or_fragments))
/// — for the loop to multicast to the group: the multicast mirror of the
/// unicast writer-channel seam (zenoh-pico `_z_send_n_msg` over the multicast
/// transport). The enum is unconditional (signature stability); the variants
/// are gated by the codec that encodes them, so a build without any data codec
/// carries an uninhabited type and a dead arm-free match.
///
/// R311mb — the large owned-message variants (`Push` / `Response` /
/// `DeclareReply`) box their payload, mirroring [`NetworkMessage`'s][nm] own
/// `Box<PushOwned>` / `Box<ResponseOwned>` / `Box<DeclareOwned>` (the small
/// `ResponseFinal`, a bare rid, stays inline). This bounds the enum to a pointer
/// rather than its 700+ byte largest variant, so a `VecDeque<MulticastTxItem>`
/// reply queue (the MCU `MulticastReplyQueue`) holds pointer-sized slots — the
/// owned payloads already heap-allocate, so the extra `Box` is marginal — and it
/// keeps clippy's `large_enum_variant` quiet across every codec subset.
///
/// [nm]: crate::network_message::NetworkMessage
#[derive(Debug)]
pub enum MulticastTxItem {
    /// A pub/sub Push (`z_put` / `z_del` over multicast). Framed via the
    /// [`encode_frame_with_push`](crate::frame_encode::encode_frame_with_push)
    /// SSOT with a freshly minted channel SN.
    #[cfg(feature = "codec-push")]
    Push {
        /// The built Push network message
        /// ([`build_push_literal`](crate::push_build::build_push_literal) and
        /// friends). Boxed (R311mb) to bound the enum size.
        push: Box<wz_codecs::push::PushOwned>,
        /// Channel selection: reliable mints on the reliable ring,
        /// best-effort on the other (multicast UDP delivery is
        /// best-effort either way; the flag governs the SN channel +
        /// the frame's R flag).
        reliable: bool,
        /// R311y227 — the app / routing QoS band. Under `transport-qos` on a
        /// group that negotiated `is_qos` it selects the per-priority TX conduit
        /// and rides the frame `ext_qos`; otherwise the emit clamps it to
        /// [`Priority::DEFAULT`] (no non-DEFAULT frame reaches a non-qos / pico
        /// receiver). A local produce with no chosen priority passes
        /// `Priority::DEFAULT` (the [`multicast_put_literal`] default).
        priority: Priority,
    },
    /// R311lq — a queryable `Response(Reply|Err)` over multicast: the
    /// reply a queryable's handler produced for a Query that arrived on
    /// the group. Staged by the observer during `dispatch_event` and
    /// drained through the AP loop's `MulticastReplySink` onto its outbound
    /// channel; the loop frames it via the
    /// [`encode_frame_with_response`](crate::frame_encode::encode_frame_with_response)
    /// SSOT and multicasts it (reliable — zenoh-pico replies on the multicast
    /// transport through the same `_z_send_n_msg` path with
    /// `Z_RELIABILITY_RELIABLE`). The querier on the group matches it to
    /// its pending Query by request id.
    #[cfg(feature = "codec-response")]
    Response {
        /// The built `Response` network message (drained from the
        /// observer's `pending_replies` via `QueryReply::into_response`).
        /// Boxed (R311mb) to bound the enum size.
        response: Box<wz_codecs::response::ResponseOwned>,
    },
    /// R311lq — the `ResponseFinal` terminating a multicast reply chain
    /// for `request_id`. Unconditionally reliable: dropping it would leave
    /// the querier's `z_get` waiting for a terminal that never re-emits.
    /// Built from the rid via
    /// [`build_response_final`](crate::response_final_build::build_response_final)
    /// and framed via
    /// [`encode_frame_with_response_final`](crate::frame_encode::encode_frame_with_response_final).
    #[cfg(feature = "codec-response-final")]
    ResponseFinal {
        /// The request id whose reply chain this frame terminates (drained
        /// from the observer's `pending_final_rids`).
        request_id: u64,
        /// R2595 — the QUERY's QoS, which the terminator carries as its
        /// replies do, and which also picks the conduit this frame rides.
        qos: crate::sample::QosLevel,
    },
    /// R311lr — a declarer-side liveliness interest-response
    /// `Declare(DeclToken|DeclFinal)` over multicast: the reply a held
    /// liveliness token produced for an `Interest` (CURRENT) that arrived on
    /// the group. Staged by the observer during `dispatch_event` and drained
    /// through the AP loop's `MulticastReplySink`
    /// [`DeclareReplySink`](crate::response_sink::DeclareReplySink) impl onto
    /// its outbound channel; the loop frames it via the
    /// [`encode_frame_with_declare`](crate::frame_encode::encode_frame_with_declare)
    /// SSOT and multicasts it (reliable — zenoh-pico's `_z_send_declare` rides
    /// `_z_send_n_msg` with `Z_RELIABILITY_RELIABLE`, src/net/primitives.c:52,
    /// which dispatches to the multicast transport when the session is
    /// multicast). The querier on the group matches it to its pending
    /// liveliness Interest by `interest_id`. Carries the owned `DeclareOwned`
    /// because the borrowed-arg sink seam resolves the keyexpr at drain (mirror
    /// of the unicast `SessionLinkActions: DeclareReplySink`, which routes the
    /// same owned form through its inherent `send_declare`).
    #[cfg(feature = "liveliness-token")]
    DeclareReply {
        /// The built `Declare` reply (a `DeclToken` for a held token, or the
        /// terminating `DeclFinal`), already owned via `Declare::try_into_owned`.
        /// Boxed (R311mb) to bound the enum size.
        declare: Box<wz_codecs::declare::DeclareOwned>,
    },
}

/// The wire datagrams one [`MulticastTxItem`] becomes, plus the channel
/// reliability the loop sends them on. `datagrams` is a single `T_MID_FRAME`
/// for a sub-budget emission, or the `T_MID_FRAGMENT` chain an oversize one
/// re-frames into (R311ko); they are sent in order. `reliable` selects the link
/// send mode — the MCU `send_to_group` ignores it (multicast UDP is best-effort
/// either way), while the AP `LinkDriver::send` maps it to
/// `Reliability::{Reliable, BestEffort}`.
#[derive(Debug)]
pub struct MulticastTxFrames {
    /// The wire datagrams to multicast, in send order (one frame, or a
    /// ring-consecutive fragment chain).
    pub datagrams: Vec<Vec<u8>>,
    /// The channel the frame rode (the reliable SN ring + the R flag).
    pub reliable: bool,
}

/// R311y227 — the multicast send-side band clamp: the app / routing priority
/// when the group negotiated `is_qos` under `transport-qos`, else
/// [`Priority::DEFAULT`]. A build WITHOUT `transport-qos` has no per-priority
/// conduit, so the band is always elided to DEFAULT — no non-DEFAULT frame can
/// ride (the pico-faithful 2-channel default), and a non-qos / pico receiver
/// never decodes an "Unknown priority" frame.
#[cfg(any(feature = "codec-push", feature = "codec-response"))]
fn effective_mcast_priority(priority: Priority, is_qos: bool) -> Priority {
    #[cfg(feature = "transport-qos")]
    {
        if is_qos {
            priority
        } else {
            Priority::DEFAULT
        }
    }
    #[cfg(not(feature = "transport-qos"))]
    {
        let _ = (priority, is_qos);
        Priority::DEFAULT
    }
}

/// R311y227 — the Frame `ext_qos` for a clamped conduit priority: `Some` only for
/// a non-DEFAULT priority (zenoh OMITS the QoS ext on a DEFAULT / Data frame; the
/// receiver decodes its ABSENCE as DEFAULT). `None` ⇒ byte-identical to the
/// pre-qos wire — the anchor the layer3 byte-equiv tests pin.
#[cfg(any(feature = "codec-push", feature = "codec-response"))]
fn frame_ext_qos(priority: Priority) -> Option<Priority> {
    (priority != Priority::DEFAULT).then_some(priority)
}

/// R2928 — the bounded queue a multicast transmission pipeline pushes onto:
/// upstream's per-priority stage of a multicast link's `TransmissionPipeline`,
/// which is built from the same queue configuration as a unicast link's
/// (`io/zenoh-transport/src/multicast/link.rs` @ `let tpc = TransmissionPipelineConf {`).
///
/// The two questions are the ones the unicast session asks of its link
/// ([`BoxedLinkDriver::wait_for_room`](crate::link::BoxedLinkDriver::wait_for_room)),
/// kept apart for the same reason: room is asked BEFORE a sequence number is
/// minted, so a message that finds none spends no SN, and the datagram is
/// enqueued only once it has one.
pub trait MulticastTxQueue {
    /// Wait, within `wait`, for room on `priority`'s lane.
    fn wait_for_room(&mut self, priority: Priority, wait: RoomWait) -> RoomAnswer;

    /// Put one wire datagram on its conduit's lane. Room was asked first; a
    /// fragment chain's stop marker is the one datagram enqueued without it,
    /// outside the bound, as upstream's ephemeral stop batch is outside its
    /// pool.
    fn enqueue(&mut self, datagram: MulticastTxDatagram);
}

/// R2929 — one datagram a push puts on the queue, with the conduit and the
/// sequence number it carries: a queue that writes later can say, as it
/// writes, which SN has reached the wire (`MulticastTxConduits::written`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastTxDatagram {
    /// The conduit's band: the effective priority the SN was minted on, and
    /// the lane the datagram takes.
    pub priority: Priority,
    /// The conduit's channel.
    pub reliable: bool,
    /// The sequence number the datagram carries.
    pub sn: u64,
    /// The wire bytes.
    pub bytes: Vec<u8>,
}

/// A queue that always has room and keeps what it is given: the pico-faithful
/// shape, where a multicast send goes straight to the socket and there is no
/// queue to be full (`multicast_tx_emit`'s backing).
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
struct UnboundedCollect(Vec<Vec<u8>>);

#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
impl MulticastTxQueue for UnboundedCollect {
    fn wait_for_room(&mut self, _priority: Priority, _wait: RoomWait) -> RoomAnswer {
        RoomAnswer::at_once(LinkRoom::Free)
    }

    fn enqueue(&mut self, datagram: MulticastTxDatagram) {
        self.0.push(datagram.bytes);
    }
}

/// Mint the channel SN for `item`, encode its network message into a
/// `T_MID_FRAME` via the matching `encode_frame_with_*` SSOT, and re-frame it
/// into a `T_MID_FRAGMENT` chain when the frame exceeds the group batch budget
/// ([`batch_size`](crate::multicast_params::MulticastParams::batch_size)), with
/// no queue in the way. The TX twin of
/// [`dispatch_multicast_inbound`](crate::multicast_rx::dispatch_multicast_inbound);
/// the caller multicasts the returned [`MulticastTxFrames::datagrams`] in order
/// on its own driver.
///
/// R2928 — this is [`multicast_tx_push`] over a queue that always has room, so
/// the wire and the SN walk have ONE producer whether or not a bounded queue
/// sits under the loop. The MCU loop sends this way, as zenoh-pico does: its
/// multicast TX writes straight to the socket.
///
/// Gated on the union of the body codecs that inhabit [`MulticastTxItem`]: with
/// none, the item is uninhabited and can never be enqueued, so the emit SSOT
/// does not exist (the loops consume the uninhabited item with an empty match).
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
pub fn multicast_tx_emit(
    item: MulticastTxItem,
    tx_sn: &mut crate::sn::MulticastTxConduits,
    params: &crate::multicast_params::MulticastParams,
) -> MulticastTxFrames {
    let reliable = multicast_tx_reliable(&item);
    let mut collect = UnboundedCollect(Vec::new());
    // Always room, so never `Congested`; the waits are never spent.
    let _ = multicast_tx_push(item, tx_sn, params, &TxQueueConf::default(), &mut collect);
    MulticastTxFrames {
        datagrams: collect.0,
        reliable,
    }
}

/// The channel `item` rides: a Push's own flag; the replies are pinned
/// reliable (a dropped reply / terminal hangs the peer's pending get, so they
/// ride the reliable SN ring + R flag — zenoh-pico parity).
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
fn multicast_tx_reliable(item: &MulticastTxItem) -> bool {
    match item {
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Push { reliable, .. } => *reliable,
        #[cfg(feature = "codec-response")]
        MulticastTxItem::Response { .. } => true,
        #[cfg(feature = "codec-response-final")]
        MulticastTxItem::ResponseFinal { .. } => true,
        #[cfg(feature = "liveliness-token")]
        MulticastTxItem::DeclareReply { .. } => true,
    }
}

/// R2928 — push `item` onto a multicast link's bounded `queue`: upstream's
/// `push_network_message` on the multicast link's pipeline
/// (`io/zenoh-transport/src/common/pipeline.rs` @ `pub(crate) fn push_network_message(`).
///
/// The message's deadline is [`PushDeadline`] over `conf`: `wait_before_drop`
/// for a droppable message, `wait_before_close` for a blocking one, each
/// fragment of a chain extending a droppable one. Room is asked before the
/// frame's SN is minted, so a message that finds none leaves its conduit's
/// ring where it was; a chain that runs out between fragments is stopped with
/// a drop marker that takes the next SN, as the unicast chain is.
///
/// `Congested` is the whole of what a multicast transport does with a message
/// that found no room, blocking or not: upstream's multicast schedule counts it
/// as a congestion drop and closes nothing
/// (`io/zenoh-transport/src/multicast/tx.rs` @ `fn schedule_on_link(&self, msg: NetworkMessageRef) -> ZResult<bool> {`),
/// where a unicast transport closes on a blocking one.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
pub fn multicast_tx_push<M, Q>(
    item: MulticastTxItem,
    tx_sn: &mut M,
    params: &crate::multicast_params::MulticastParams,
    conf: &TxQueueConf,
    queue: &mut Q,
) -> PushOutcome
where
    M: MulticastTxMint + ?Sized,
    Q: MulticastTxQueue + ?Sized,
{
    // R2931 — the meta is resolved once, by the function a producer also asks
    // for the conduit it must hold (`multicast_tx_conduit`), so the conduit
    // locked and the conduit minted on cannot come from two readings.
    let meta = frame_meta(&item, params);
    match item {
        // TxData: mint the channel SN, wrap in a T_MID_FRAME (frame_encode
        // SSOT), and let multicast_frame_or_fragments re-frame an oversize
        // frame into a T_MID_FRAGMENT chain riding the same minted SN + the
        // follow-on mints (R311ko, zenoh-pico common-TX parity). A dropped
        // datagram leaves an SN gap inside receivers' half-window — though a
        // hole in a fragment chain aborts that chain at every receiver, as on
        // pico — so the loop's send is best-effort like the JOIN beacon.
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Push { push, .. } => push_frame(
            meta,
            |sn| {
                crate::frame_encode::encode_frame_with_push_qos(
                    sn,
                    *push,
                    meta.reliable,
                    meta.ext_qos,
                )
            },
            tx_sn,
            params,
            conf,
            queue,
        ),
        // R311lq — queryable reply egress. Reliable like a reliable-ring put
        // (zenoh-pico replies via the same `_z_send_n_msg` multicast TX with
        // `Z_RELIABILITY_RELIABLE`); a large reply re-frames as a fragment
        // chain exactly like an oversize Push.
        #[cfg(feature = "codec-response")]
        MulticastTxItem::Response { response } => {
            push_frame(
                meta,
                |sn| {
                    crate::frame_encode::encode_frame_with_response_qos(
                        sn,
                        *response,
                        /* reliable = */ true,
                        meta.ext_qos,
                    )
                },
                tx_sn,
                params,
                conf,
                queue,
            )
        }
        // R311lq — the terminal of a multicast reply chain. Always reliable and
        // always tiny (a single VLE rid), so it never reaches the fragment
        // budget: one minted reliable-ring SN, one frame. Mirrors the unicast
        // `send_response_final` (reliability pinned).
        #[cfg(feature = "codec-response-final")]
        MulticastTxItem::ResponseFinal { request_id, qos } => {
            // Uniform egress: a ResponseFinal is a single tiny VLE rid that never
            // reaches the budget, so `push_frame` enqueues the one frame with no
            // follow-on mint (byte-identical to a single send) - one path for
            // all four variants rather than a special case.
            push_frame(
                meta,
                |sn| {
                    crate::frame_encode::encode_frame_with_response_final_qos(
                        sn,
                        crate::response_final_build::build_response_final(request_id, qos),
                        /* reliable = */ true,
                        meta.ext_qos,
                    )
                },
                tx_sn,
                params,
                conf,
                queue,
            )
        }
        // R311lr — declarer-side liveliness interest-response egress. Reliable —
        // zenoh-pico's `_z_send_declare` rides `_z_send_n_msg` with
        // `Z_RELIABILITY_RELIABLE` (src/net/primitives.c:52); a large held-token
        // keyexpr re-frames as a fragment chain exactly like an oversize Push.
        #[cfg(feature = "liveliness-token")]
        MulticastTxItem::DeclareReply { declare } => {
            push_frame(
                meta,
                |sn| {
                    crate::frame_encode::encode_frame_with_declare(
                        sn, *declare, /* reliable = */ true,
                    )
                },
                tx_sn,
                params,
                conf,
                queue,
            )
        }
    }
}

/// zenoh's `is_droppable`: a best-effort message, or one whose congestion
/// control is `Drop`
/// (`commons/zenoh-protocol/src/network/mod.rs` @ `!self.is_reliable() || self.congestion_control() == CongestionControl::Drop`).
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
fn is_droppable(reliable: bool, congestion: crate::qos::CongestionControl) -> bool {
    !reliable || congestion == crate::qos::CongestionControl::Drop
}

/// R2931 — what a push of `item` onto a group of `params` must know besides
/// its bytes: the conduit, the frame's `ext_qos`, the channel, and whether the
/// message may be dropped. The one reading of an item's QoS on the TX side;
/// [`multicast_tx_push`] and [`multicast_tx_conduit`] both ask it.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
fn frame_meta(
    item: &MulticastTxItem,
    params: &crate::multicast_params::MulticastParams,
) -> FrameMeta {
    // A declare-reply-only build pins its one band and never reads the group.
    let _ = params;
    match item {
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Push {
            push,
            reliable,
            priority,
        } => {
            // R311y227 — clamp the app / routing band to DEFAULT unless the group
            // negotiated `is_qos` (else a non-qos / pico receiver bails "Unknown
            // priority"). Under `transport-qos` on a qos group the clamped `eff`
            // selects the per-priority TX conduit AND rides the frame `ext_qos`;
            // the fragment re-frame re-emits that SAME `ext_qos` and mints its
            // follow-ons on the SAME conduit. `None` / DEFAULT is byte-identical
            // to the pre-qos wire.
            let eff = effective_mcast_priority(*priority, params.is_qos);
            // R2928 — the congestion control comes off the Push's own ext_qos,
            // as upstream's `congestion_control()` reads it
            // (`commons/zenoh-protocol/src/network/mod.rs` @ `NetworkBodyRef::Push(msg) => msg.ext_qos.get_congestion_control(),`).
            let congestion = crate::declare_ext_qos::read_push_qos(push).congestion();
            FrameMeta {
                priority: eff,
                ext_qos: frame_ext_qos(eff),
                reliable: *reliable,
                droppable: is_droppable(*reliable, congestion),
            }
        }
        // R2594 — the band comes off the Response's own `ext_qos`, clamped
        // exactly as a Push's is, because upstream's transport reads a
        // Response's band there:
        // `commons/zenoh-protocol/src/network/mod.rs` @ `NetworkBodyRef::Response(msg) => msg.ext_qos.get_priority(),`
        // This arm used to pin DEFAULT with a note that "zenoh treats reply
        // priority as a separate concern", which that match arm refutes. A
        // non-qos group still clamps to DEFAULT, byte-identical to before.
        #[cfg(feature = "codec-response")]
        MulticastTxItem::Response { response } => {
            let qos = crate::declare_ext_qos::read_response_qos(response);
            let eff = effective_mcast_priority(qos.priority(), params.is_qos);
            FrameMeta {
                priority: eff,
                ext_qos: frame_ext_qos(eff),
                reliable: true,
                droppable: is_droppable(true, qos.congestion()),
            }
        }
        // R2595 — the terminator rides its query's band, clamped as the
        // Response arm above is, rather than a pinned DEFAULT.
        #[cfg(feature = "codec-response-final")]
        MulticastTxItem::ResponseFinal { qos, .. } => {
            let eff = effective_mcast_priority(qos.priority(), params.is_qos);
            FrameMeta {
                priority: eff,
                ext_qos: frame_ext_qos(eff),
                reliable: true,
                droppable: is_droppable(true, qos.congestion()),
            }
        }
        // The declare reply is DEFAULT-band: no frame ext_qos, no per-priority
        // conduit.
        #[cfg(feature = "liveliness-token")]
        MulticastTxItem::DeclareReply { declare } => FrameMeta {
            priority: Priority::DEFAULT,
            ext_qos: None,
            reliable: true,
            droppable: is_droppable(
                true,
                crate::declare_ext_qos::read_declare_qos(declare).congestion(),
            ),
        },
    }
}

/// R2931 — the conduit a push of `item` onto a group of `params` mints on:
/// the effective (clamped) band. A producer that holds one conduit at a time,
/// as upstream's pipeline holds one priority's stage while it waits for a
/// batch (`io/zenoh-transport/src/common/pipeline.rs` @ `pub(crate) fn push_network_message(`),
/// asks this for the conduit to lock and then pushes against it
/// ([`MulticastTxConduit`]).
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
pub fn multicast_tx_conduit(
    item: &MulticastTxItem,
    params: &crate::multicast_params::MulticastParams,
) -> Priority {
    frame_meta(item, params).priority
}

/// R2931 — where a push mints its sequence numbers: the whole set of a group's
/// conduits ([`MulticastTxConduits`](crate::sn::MulticastTxConduits)), or the
/// one conduit a producer holds ([`MulticastTxConduit`]).
pub trait MulticastTxMint {
    /// Mint the next SN on the `(priority, reliable)` conduit.
    fn mint(&mut self, priority: Priority, reliable: bool) -> u64;
    /// The SN ring's mask.
    fn mask(&self) -> u64;
}

impl MulticastTxMint for crate::sn::MulticastTxConduits {
    fn mint(&mut self, priority: Priority, reliable: bool) -> u64 {
        crate::sn::MulticastTxConduits::mint(self, priority, reliable)
    }

    fn mask(&self) -> u64 {
        crate::sn::MulticastTxConduits::mask(self)
    }
}

/// R2931 — one conduit, held by the producer that pushes on it: its band and
/// its SN state. A push that would mint on any other band is a producer that
/// locked the wrong conduit, which would put two producers' SNs on one ring
/// unsynchronised; that is refused rather than minted.
pub struct MulticastTxConduit<'a> {
    priority: Priority,
    sn: &'a mut crate::sn::TxSn,
}

impl<'a> MulticastTxConduit<'a> {
    /// The `priority` conduit, whose state is `sn`.
    pub fn new(priority: Priority, sn: &'a mut crate::sn::TxSn) -> Self {
        Self { priority, sn }
    }
}

impl MulticastTxMint for MulticastTxConduit<'_> {
    fn mint(&mut self, priority: Priority, reliable: bool) -> u64 {
        assert_eq!(
            priority, self.priority,
            "a push minted on a conduit its producer does not hold"
        );
        self.sn.mint(reliable)
    }

    fn mask(&self) -> u64 {
        self.sn.mask
    }
}

/// What [`push_frame`] needs to know of a message besides its bytes.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
#[derive(Clone, Copy)]
struct FrameMeta {
    /// The effective (clamped) band: the conduit the SN mints on and the lane
    /// the datagrams take.
    priority: Priority,
    /// The frame's `ext_qos` — `Some` iff `priority` is not DEFAULT.
    ext_qos: Option<Priority>,
    reliable: bool,
    droppable: bool,
}

/// R2928 — one message's walk onto the queue: ask for room, mint, encode, and
/// enqueue the frame, or stream it as a fragment chain that asks again before
/// each further fragment. `encode` turns the minted SN into the framed
/// message.
///
/// The chain's bytes are [`FragmentChain`](crate::frame_encode::FragmentChain)'s,
/// the one producer `multicast_frame_or_fragments` collects too, and its SNs are
/// ring-consecutive from the frame's: each further fragment mints exactly one,
/// as that function's up-front mints do, so the two agree on the wire and on
/// the ring whenever there is room throughout.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
fn push_frame<M: MulticastTxMint + ?Sized, Q: MulticastTxQueue + ?Sized>(
    meta: FrameMeta,
    encode: impl FnOnce(u64) -> Vec<u8>,
    tx_sn: &mut M,
    params: &crate::multicast_params::MulticastParams,
    conf: &TxQueueConf,
    queue: &mut Q,
) -> PushOutcome {
    let FrameMeta {
        priority,
        ext_qos,
        reliable,
        droppable,
    } = meta;
    let mut deadline = PushDeadline::new(droppable, conf);
    let has_room = |queue: &mut Q, deadline: &mut PushDeadline| {
        let answer = queue.wait_for_room(priority, deadline.ask());
        deadline.spend(answer.waited_us);
        // A queue whose writer is gone is not congested: what is enqueued on
        // it is lost with the link, as the unicast push treats it.
        answer.room != LinkRoom::Congested
    };
    if !has_room(queue, &mut deadline) {
        return PushOutcome::Congested;
    }
    let sn = tx_sn.mint(priority, reliable);
    let frame = encode(sn);
    let mtu = params.batch_size as usize;
    #[cfg(feature = "transport-fragmentation")]
    if frame.len() > mtu {
        let body = crate::frame_encode::frame_wire_body(&frame, sn, ext_qos);
        let mut chain =
            crate::frame_encode::FragmentChain::new(body, reliable, mtu, sn, tx_sn.mask(), ext_qos);
        let mut emitted = 0usize;
        while chain.remaining_fragments() > 0 {
            // The SN the fragment this iteration sends carries — and the one
            // the stop marker takes if there is no room for it.
            let this_sn = chain.next_sn();
            if emitted > 0 {
                if !has_room(queue, &mut deadline) {
                    let marker =
                        crate::frame_encode::build_fragment_drop_wire(this_sn, reliable, ext_qos);
                    tx_sn.mint(priority, reliable);
                    queue.enqueue(MulticastTxDatagram {
                        priority,
                        reliable,
                        sn: this_sn,
                        bytes: marker,
                    });
                    return PushOutcome::Congested;
                }
                tx_sn.mint(priority, reliable);
            }
            let Some(fragment) = chain.next() else {
                // `remaining_fragments() > 0` and `next() == None` are the same
                // predicate negated, so this arm is unreachable.
                break;
            };
            queue.enqueue(MulticastTxDatagram {
                priority,
                reliable,
                sn: this_sn,
                bytes: fragment,
            });
            emitted += 1;
            deadline.next_fragment();
        }
        return PushOutcome::Pushed;
    }
    #[cfg(not(feature = "transport-fragmentation"))]
    let _ = (ext_qos, mtu);
    queue.enqueue(MulticastTxDatagram {
        priority,
        reliable,
        sn,
        bytes: frame,
    });
    PushOutcome::Pushed
}

/// Convenience builder: a literal-keyexpr Put as a queued [`MulticastTxItem`]
/// on the RELIABLE channel — zenoh's put default (zenoh-pico
/// `Z_RELIABILITY_DEFAULT = Z_RELIABILITY_RELIABLE`, api/constants.h:203,
/// multicast included; the reliable channel has no retransmit on either
/// implementation — pico rx.c "only monotonic SNs are ensured" — so the flag
/// selects the SN ring + frame R flag, not a delivery guarantee). Composes
/// [`build_push_literal`](crate::push_build::build_push_literal); richer pushes
/// (Del / best-effort / aliased keyexpr / metadata) construct the item
/// directly.
#[cfg(feature = "codec-push")]
pub fn multicast_put_literal(
    keyexpr_suffix: &str,
    payload: &[u8],
) -> Result<MulticastTxItem, sce_forge_runtime::codec::CodecError> {
    Ok(MulticastTxItem::Push {
        push: Box::new(crate::push_build::build_push_literal(
            keyexpr_suffix,
            payload,
        )?),
        reliable: true,
        // The convenience builder produces a DEFAULT-band Put (the pico-faithful
        // put default); a prioritized multicast produce constructs the item
        // directly with its chosen `priority` (mirrors the unicast publish_qos).
        priority: Priority::DEFAULT,
    })
}

/// R2848 (`transport-stats`) — what a queued item counts as when it enters the
/// transport: its registry class and the band it carries.
///
/// Upstream counts a sent network message by the message's OWN band
/// (`io/zenoh-transport/src/multicast/tx.rs` @ `self.link_stats.inc_network_message(zenoh_stats::Tx, msg);`),
/// which is the band BEFORE a non-QoS group clamps the frame to DEFAULT, just
/// as the unicast send seam records the caller's band before its own clamp.
/// A Push's band rides beside it on the item; every other variant carries its
/// band in its own `ext_qos`.
///
/// The alias resolver answers `None`: the multicast egress keeps no id space
/// of its own, and every producer re-literalizes a Push before queueing it
/// (the router's group leg says why — a group leaf never saw the inbound
/// face's declarations), so an item's key expression is already the literal
/// its space is read from.
#[cfg(all(
    feature = "transport-stats",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
pub fn multicast_tx_stats_class(
    item: &MulticastTxItem,
) -> (crate::qos::Priority, crate::stats::NetworkStatsClass) {
    use crate::stats::{MessageLabel, NetworkStatsClass};
    match item {
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Push { push, priority, .. } => (
            *priority,
            crate::network_message::push_stats_class(push, |_| None),
        ),
        #[cfg(feature = "codec-response")]
        MulticastTxItem::Response { response } => (
            crate::declare_ext_qos::read_response_qos(response).priority(),
            crate::network_message::response_stats_class(response, |_| None),
        ),
        #[cfg(feature = "codec-response-final")]
        MulticastTxItem::ResponseFinal { qos, .. } => (
            qos.priority(),
            NetworkStatsClass::control(MessageLabel::ResponseFinal),
        ),
        #[cfg(feature = "liveliness-token")]
        MulticastTxItem::DeclareReply { declare } => (
            crate::declare_ext_qos::read_declare_qos(declare).priority(),
            NetworkStatsClass::control(MessageLabel::Declare),
        ),
    }
}

/// R2929 — what a multicast transport's counts need of a message, taken before
/// the push consumes it: whether the message is then counted as sent or as a
/// congestion drop is known only after, and by then the item is on the wire or
/// gone. Without `transport-stats` there is nothing to count and the tally is
/// empty.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
pub struct MulticastTxTally {
    #[cfg(feature = "transport-stats")]
    priority: Priority,
    #[cfg(feature = "transport-stats")]
    class: crate::stats::NetworkStatsClass,
}

#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
impl MulticastTxTally {
    /// The tally of `item`, by its own band and class
    /// (`multicast_tx_stats_class`).
    pub fn of(item: &MulticastTxItem) -> Self {
        #[cfg(feature = "transport-stats")]
        {
            let (priority, class) = multicast_tx_stats_class(item);
            Self { priority, class }
        }
        #[cfg(not(feature = "transport-stats"))]
        {
            let _ = item;
            Self {}
        }
    }

    /// The message's own band.
    #[cfg(feature = "transport-stats")]
    pub fn priority(&self) -> Priority {
        self.priority
    }

    /// The message's class.
    #[cfg(feature = "transport-stats")]
    pub fn class(&self) -> &crate::stats::NetworkStatsClass {
        &self.class
    }
}

// R311y227 — the emit-level witness: `multicast_tx_emit` clamps the band by the
// group's `is_qos`, selects the per-priority TX conduit, and writes the frame
// `ext_qos` — the composition the sn.rs (conduit) + frame_encode (wire) unit
// tests exercise separately. Gated on `transport-qos` (the per-priority conduit)
// + `codec-push` (the Push item) — `transport-qos` pulls `codec-frame`, so the
// real `parse_inbound` decoder is in scope.
#[cfg(all(test, feature = "transport-qos", feature = "codec-push"))]
mod qos_emit_tests {
    use super::*;
    use crate::inbound::{parse_inbound, InboundFrame};
    use crate::multicast_params::MulticastParams;
    use crate::qos::Priority;
    use crate::sn::{mask_from_res, MulticastTxConduits};
    use crate::WhatAmI;

    fn params(is_qos: bool) -> MulticastParams {
        MulticastParams {
            version: 0x09,
            whatami: WhatAmI::Peer,
            zid: alloc::vec![1, 2, 3, 4],
            lease_ms: 5_000,
            join_interval_ms: 50,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos,
            tx_queue: TxQueueConf::default(),
        }
    }

    /// On a qos group a non-DEFAULT-priority Push emits a Frame that carries the
    /// on-wire `ext_qos` (the priority `parse_inbound` recovers) AND mints on that
    /// priority's own conduit — the DEFAULT ring stays untouched.
    #[test]
    fn qos_group_emits_frame_ext_qos_and_mints_on_the_priority_conduit() {
        let params = params(true);
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let item = MulticastTxItem::Push {
            push: Box::new(crate::push_build::build_push_literal("k", b"v").unwrap()),
            reliable: true,
            priority: Priority::RealTime,
        };
        let frames = multicast_tx_emit(item, &mut tx, &params);
        assert_eq!(frames.datagrams.len(), 1);
        let InboundFrame::Frame { priority, sn, .. } = parse_inbound(&frames.datagrams[0]).unwrap()
        else {
            panic!("expected a Frame");
        };
        assert_eq!(
            priority,
            Priority::RealTime,
            "the emitted frame carries its ext_qos band"
        );
        assert_eq!(sn, 0, "first mint on the RealTime conduit is SN 0");
        // The DEFAULT conduit is untouched — proof the mint went to RealTime's ring.
        assert_eq!(tx.advertise_default().next_reliable, 0);
        assert_eq!(
            tx.advertise_per_priority()[Priority::RealTime as usize].next_reliable,
            1
        );
    }

    /// A NON-qos group clamps the same Push to DEFAULT: no frame ext_qos
    /// (byte-identical to the pre-qos wire), minted on the DEFAULT ring — a pico /
    /// non-qos receiver never sees an "Unknown priority" frame.
    #[test]
    fn non_qos_group_clamps_to_default_no_ext_qos() {
        let params = params(false);
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let item = MulticastTxItem::Push {
            push: Box::new(crate::push_build::build_push_literal("k", b"v").unwrap()),
            reliable: true,
            priority: Priority::RealTime, // requested high, but the group is non-qos
        };
        let frames = multicast_tx_emit(item, &mut tx, &params);
        let InboundFrame::Frame {
            priority, has_ext, ..
        } = parse_inbound(&frames.datagrams[0]).unwrap()
        else {
            panic!("expected a Frame");
        };
        assert_eq!(
            priority,
            Priority::DEFAULT,
            "clamped to DEFAULT: an absent ext decodes as DEFAULT"
        );
        assert!(
            !has_ext,
            "no frame transport ext on a non-qos clamp (byte-identical to pre-qos)"
        );
        assert_eq!(
            tx.advertise_default().next_reliable,
            1,
            "minted on the DEFAULT conduit"
        );
    }
}

// R2928 — the multicast push against a scripted queue: room before the mint,
// the deadline each ask carries, and a chain that runs out part-way.
#[cfg(all(test, feature = "codec-push"))]
mod push_tests {
    use super::*;
    use crate::multicast_params::MulticastParams;
    use crate::sn::{mask_from_res, MulticastTxConduits};
    use crate::WhatAmI;
    use alloc::collections::VecDeque;

    fn params(batch_size: u16) -> MulticastParams {
        MulticastParams {
            version: 0x09,
            whatami: WhatAmI::Peer,
            zid: alloc::vec![1, 2, 3, 4],
            lease_ms: 5_000,
            join_interval_ms: 50,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size,
            is_qos: false,
            tx_queue: TxQueueConf::default(),
        }
    }

    /// Answers each ask from a script (room once the script is spent) and
    /// keeps every ask and every datagram.
    #[derive(Default)]
    struct Scripted {
        answers: VecDeque<LinkRoom>,
        asks: Vec<RoomWait>,
        enqueued: Vec<Vec<u8>>,
        /// The SN each enqueued datagram was declared to carry.
        sns: Vec<u64>,
    }

    impl MulticastTxQueue for Scripted {
        fn wait_for_room(&mut self, _priority: Priority, wait: RoomWait) -> RoomAnswer {
            self.asks.push(wait);
            RoomAnswer::at_once(self.answers.pop_front().unwrap_or(LinkRoom::Free))
        }

        fn enqueue(&mut self, datagram: MulticastTxDatagram) {
            self.sns.push(datagram.sn);
            self.enqueued.push(datagram.bytes);
        }
    }

    fn put(reliable: bool, payload: &[u8]) -> MulticastTxItem {
        MulticastTxItem::Push {
            push: Box::new(crate::push_build::build_push_literal("k", payload).unwrap()),
            reliable,
            priority: Priority::DEFAULT,
        }
    }

    /// A message that finds no room leaves nothing on the queue and its
    /// conduit's ring where it was: the next message takes the SN it would
    /// have.
    #[test]
    fn a_message_that_finds_no_room_spends_no_sequence_number() {
        let params = params(2_048);
        let conf = TxQueueConf::default();
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Scripted {
            answers: [LinkRoom::Congested].into(),
            ..Default::default()
        };
        let outcome = multicast_tx_push(put(true, b"v"), &mut tx, &params, &conf, &mut queue);
        assert_eq!(outcome, PushOutcome::Congested);
        assert!(queue.enqueued.is_empty());
        assert_eq!(tx.advertise_default().next_reliable, 0);

        let outcome = multicast_tx_push(put(true, b"v"), &mut tx, &params, &conf, &mut queue);
        assert_eq!(outcome, PushOutcome::Pushed);
        assert_eq!(queue.enqueued.len(), 1);
        assert_eq!(tx.advertise_default().next_reliable, 1);
    }

    /// A droppable message asks with `wait_before_drop`; a blocking one with
    /// `wait_before_close` — the configured values, not the defaults.
    #[cfg(feature = "codec-response-final")]
    #[test]
    fn each_message_asks_with_the_wait_its_congestion_control_names() {
        let params = params(2_048);
        let conf = TxQueueConf {
            wait_before_drop_us: 7,
            wait_before_close_us: 11,
            ..TxQueueConf::default()
        };
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Scripted::default();
        // A best-effort put is droppable whatever its congestion control.
        multicast_tx_push(put(false, b"v"), &mut tx, &params, &conf, &mut queue);
        let blocking = crate::sample::QosLevel::from_parts(
            Priority::DEFAULT,
            crate::qos::CongestionControl::Block,
            false,
        );
        let terminal = MulticastTxItem::ResponseFinal {
            request_id: 1,
            qos: blocking,
        };
        multicast_tx_push(terminal, &mut tx, &params, &conf, &mut queue);
        assert_eq!(
            queue.asks,
            [
                RoomWait::Drop { wait_us: 7 },
                RoomWait::Block { wait_us: 11 }
            ]
        );
    }

    /// With room throughout, the push puts on the queue exactly what the
    /// queue-less emit returns — the same bytes, the same SN walk — for a
    /// message that fragments.
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn with_room_throughout_a_chain_is_the_one_the_emit_returns() {
        let params = params(128);
        let payload = [0x5a; 1_000];
        let mut emit_tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let emitted = multicast_tx_emit(put(true, &payload), &mut emit_tx, &params);
        assert!(emitted.datagrams.len() > 2, "the message fragments");

        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Scripted::default();
        let outcome = multicast_tx_push(
            put(true, &payload),
            &mut tx,
            &params,
            &TxQueueConf::default(),
            &mut queue,
        );
        assert_eq!(outcome, PushOutcome::Pushed);
        assert_eq!(queue.enqueued, emitted.datagrams);
        assert_eq!(
            tx.advertise_default().next_reliable,
            emitted.datagrams.len() as u64
        );
        // Against the whole-chain producer the pre-R2928 emit used.
        let mut whole_tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let sn = whole_tx.mint(Priority::DEFAULT, true);
        let frame = crate::frame_encode::encode_frame_with_push_qos(
            sn,
            crate::push_build::build_push_literal("k", &payload).unwrap(),
            true,
            None,
        );
        let whole = crate::frame_encode::multicast_frame_or_fragments(
            frame,
            sn,
            true,
            params.batch_size as usize,
            &mut whole_tx,
            None,
        );
        assert_eq!(queue.enqueued, whole);
        assert_eq!(
            whole_tx.advertise_default().next_reliable,
            tx.advertise_default().next_reliable
        );
    }

    /// A chain that finds no room part-way is stopped: the fragments already
    /// out, then a drop marker on the next SN, which it spends. Each further
    /// ask carries the extended deadline, doubling per fragment.
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn a_chain_that_runs_out_part_way_ends_with_a_drop_marker_on_the_next_sn() {
        use crate::inbound::{parse_inbound, InboundFrame};
        let params = params(128);
        let conf = TxQueueConf::default();
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Scripted {
            answers: [LinkRoom::Free, LinkRoom::Free, LinkRoom::Congested].into(),
            ..Default::default()
        };
        let outcome = multicast_tx_push(
            put(true, &[0x5a; 1_000]),
            &mut tx,
            &params,
            &conf,
            &mut queue,
        );
        assert_eq!(outcome, PushOutcome::Congested);
        assert_eq!(queue.enqueued.len(), 3, "two fragments, then the marker");
        let sns: Vec<(u64, bool)> = queue
            .enqueued
            .iter()
            .map(|d| match parse_inbound(d).unwrap() {
                InboundFrame::Fragment { sn, markers, .. } => (sn, markers.dropped),
                _ => panic!("expected a Fragment"),
            })
            .collect();
        assert_eq!(sns, [(0, false), (1, false), (2, true)]);
        // R2929 — each datagram is declared to the queue with the SN it
        // carries on the wire.
        assert_eq!(queue.sns, [0, 1, 2]);
        assert_eq!(tx.advertise_default().next_reliable, 3);
        let step = conf.wait_before_drop_us;
        assert_eq!(
            queue.asks,
            [
                RoomWait::Drop { wait_us: step },
                RoomWait::Drop {
                    wait_us: step + 2 * step
                },
                RoomWait::Drop {
                    wait_us: step + 2 * step + 4 * step
                },
            ]
        );
    }

    /// R2931 — a producer that holds one conduit pushes against it alone: the
    /// band it asks for is the CLAMPED band (a non-QoS group puts every band
    /// on DEFAULT), and the push mints on that conduit's ring.
    #[test]
    fn a_held_conduit_takes_the_push_on_its_own_ring() {
        let params = params(2_048);
        let conf = TxQueueConf::default();
        let item = MulticastTxItem::Push {
            push: Box::new(crate::push_build::build_push_literal("k", b"v").unwrap()),
            reliable: true,
            priority: Priority::RealTime,
        };
        let band = multicast_tx_conduit(&item, &params);
        assert_eq!(band, Priority::DEFAULT, "a non-QoS group clamps every band");
        let mut sn = crate::sn::TxSn::new(mask_from_res(params.seq_num_res));
        let mut queue = Scripted::default();
        let outcome = multicast_tx_push(
            item,
            &mut MulticastTxConduit::new(band, &mut sn),
            &params,
            &conf,
            &mut queue,
        );
        assert_eq!(outcome, PushOutcome::Pushed);
        assert_eq!(queue.sns, [0]);
        assert_eq!(sn.next_reliable, 1);
        assert_eq!(sn.next_best_effort, 0);
    }

    /// R2931 — the control of the one above: a push whose band is not the one
    /// held is refused, not minted on a ring another producer may hold.
    #[test]
    #[should_panic(expected = "a push minted on a conduit its producer does not hold")]
    fn a_push_on_a_conduit_its_producer_does_not_hold_is_refused() {
        let params = params(2_048);
        let mut sn = crate::sn::TxSn::new(mask_from_res(params.seq_num_res));
        let _ = multicast_tx_push(
            put(true, b"v"),
            &mut MulticastTxConduit::new(Priority::Background, &mut sn),
            &params,
            &TxQueueConf::default(),
            &mut Scripted::default(),
        );
    }
}

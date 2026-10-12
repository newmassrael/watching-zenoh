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
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "liveliness-token"
    )
))]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// R311y227 — the per-priority multicast conduit send-side band type. R2928 —
// unconditional: every queue lane is named by it, whichever codecs are built.
use crate::qos::Priority;

#[cfg(feature = "alloc")]
use crate::link::{RoomAnswer, RoomWait};
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
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
    #[cfg(all(feature = "alloc", feature = "codec-push"))]
    Push {
        /// The built Push network message
        /// ([`build_push_literal`](crate::push_build::build_push_literal) and
        /// friends). Boxed (R311mb) to bound the enum size.
        push: Box<crate::wire::PushOwned>,
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
    #[cfg(all(feature = "alloc", feature = "codec-response"))]
    Response {
        /// The built `Response` network message (drained from the
        /// observer's `pending_replies` via `QueryReply::into_response`).
        /// Boxed (R311mb) to bound the enum size.
        response: Box<crate::wire::ResponseOwned>,
    },
    /// R311lq — the `ResponseFinal` terminating a multicast reply chain
    /// for `request_id`. Unconditionally reliable: dropping it would leave
    /// the querier's `z_get` waiting for a terminal that never re-emits.
    /// Built from the rid via
    /// [`build_response_final`](crate::response_final_build::build_response_final)
    /// and framed via
    /// [`encode_frame_with_response_final`](crate::frame_encode::encode_frame_with_response_final).
    #[cfg(all(feature = "alloc", feature = "codec-response-final"))]
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
    #[cfg(all(feature = "alloc", feature = "liveliness-token"))]
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
#[cfg(feature = "alloc")]
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
#[cfg(any(
    all(
        feature = "alloc",
        any(feature = "codec-push", feature = "codec-response")
    ),
    all(feature = "codec-push", feature = "transport-tx-lend")
))]
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
#[cfg(any(
    all(
        feature = "alloc",
        any(feature = "codec-push", feature = "codec-response")
    ),
    all(feature = "codec-push", feature = "transport-tx-lend")
))]
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
///
/// Heap profile only: the datagrams it takes are vectors. A build with no allocator
/// frames into one buffer lent by the caller (`multicast_tx_emit_lent`).
#[cfg(feature = "alloc")]
pub trait MulticastTxQueue {
    /// Wait, within `wait`, for room on `priority`'s lane.
    fn wait_for_room(&mut self, priority: Priority, wait: RoomWait) -> RoomAnswer;

    /// Put one wire datagram on its conduit's lane. Room was asked first; a
    /// fragment chain's stop marker is the one datagram enqueued without it,
    /// outside the bound, as upstream's ephemeral stop batch is outside its
    /// pool.
    fn enqueue(&mut self, datagram: MulticastTxDatagram);

    /// R3264 — ARCHITECTURE section 9.1 on the multicast TX: put one datagram
    /// on `priority`'s lane by having it ENCODED straight into a slot the queue
    /// lends, so the frame is never a vector of its own. `fill` writes the
    /// frame into the slot it is handed and answers whether the slot now holds
    /// the datagram to send (`false`: the frame does not fit the slot, or is
    /// past the group's batch and must be fragmented); `want` is the most the
    /// frame can need. The queue may hand `fill` a smaller slot first and a
    /// larger one after a `false`. Answers whether the datagram was enqueued;
    /// `false` means nothing was, and the caller encodes on the heap with the
    /// sequence number `sn` it already minted, as the unicast lend falls back.
    ///
    /// The default lends nothing, which is every queue that has no pool (the
    /// MCU loop's, the collecting one behind `multicast_tx_emit`).
    #[cfg(feature = "transport-tx-lend")]
    fn enqueue_lent(
        &mut self,
        priority: Priority,
        reliable: bool,
        sn: u64,
        want: usize,
        fill: &mut dyn FnMut(&mut crate::tx_buf::SliceTxBuf<'_>) -> bool,
    ) -> bool {
        let _ = (priority, reliable, sn, want, fill);
        false
    }
}

/// R2929 — one datagram a push puts on the queue, with the conduit and the
/// sequence number it carries: a queue that writes later can say, as it
/// writes, which SN has reached the wire (`MulticastTxConduits::written`).
#[cfg(feature = "alloc")]
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
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
struct UnboundedCollect(Vec<Vec<u8>>);

#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
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
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
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
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
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
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
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
    // R2937 — the meta is resolved once, by the function a producer also asks
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
            wz_codecs::push::Push::MAX_ENCODED_BYTES,
            crate::frame_encode::push_body(&push),
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
        MulticastTxItem::Response { response } => push_frame(
            // `meta.reliable` is pinned true for a reply (`frame_meta`).
            meta,
            wz_codecs::response::Response::MAX_ENCODED_BYTES,
            crate::frame_encode::response_body(&response),
            tx_sn,
            params,
            conf,
            queue,
        ),
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
            let response_final = crate::response_final_build::build_response_final(request_id, qos);
            push_frame(
                meta,
                wz_codecs::response_final::ResponseFinal::MAX_ENCODED_BYTES,
                crate::frame_encode::response_final_body(&response_final),
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
        // `meta` pins a declare reply reliable and DEFAULT-band (no ext_qos),
        // the frame `encode_frame_with_declare` writes.
        MulticastTxItem::DeclareReply { declare } => push_frame(
            meta,
            wz_codecs::declare::Declare::MAX_ENCODED_BYTES,
            crate::frame_encode::declare_body(&declare),
            tx_sn,
            params,
            conf,
            queue,
        ),
    }
}

/// zenoh's `is_droppable`: a best-effort message, or one whose congestion
/// control is `Drop`
/// (`commons/zenoh-protocol/src/network/mod.rs` @ `!self.is_reliable() || self.congestion_control() == CongestionControl::Drop`).
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
fn is_droppable(reliable: bool, congestion: crate::qos::CongestionControl) -> bool {
    !reliable || congestion == crate::qos::CongestionControl::Drop
}

/// R2937 — what a push of `item` onto a group of `params` must know besides
/// its bytes: the conduit, the frame's `ext_qos`, the channel, and whether the
/// message may be dropped. The one reading of an item's QoS on the TX side;
/// [`multicast_tx_push`] and [`multicast_tx_conduit`] both ask it.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
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

/// R2937 — the conduit a push of `item` onto a group of `params` mints on:
/// the effective (clamped) band. A producer that holds one conduit at a time,
/// as upstream's pipeline holds one priority's stage while it waits for a
/// batch (`io/zenoh-transport/src/common/pipeline.rs` @ `pub(crate) fn push_network_message(`),
/// asks this for the conduit to lock and then pushes against it
/// ([`MulticastTxConduit`]).
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
pub fn multicast_tx_conduit(
    item: &MulticastTxItem,
    params: &crate::multicast_params::MulticastParams,
) -> Priority {
    frame_meta(item, params).priority
}

/// R2937 — where a push mints its sequence numbers: the whole set of a group's
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

/// R2937 — one conduit, held by the producer that pushes on it: its band and
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
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
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
/// each further fragment. `body` encodes the network message the frame carries
/// (at most `worst_case` bytes), behind the frame header the minted SN starts.
///
/// R3264 — under `transport-tx-lend` the frame is first offered to the queue
/// to be encoded straight into a slot it lends
/// ([`MulticastTxQueue::enqueue_lent`]), as the unicast send offers its link a
/// lend; a queue that lends nothing, or a frame past the group's batch (which
/// is fragmented from the heap), takes the heap path below, with the same SN
/// and the same bytes: one envelope encoder writes both.
///
/// The chain's bytes are [`FragmentChain`](crate::frame_encode::FragmentChain)'s,
/// the one producer `multicast_frame_or_fragments` collects too, and its SNs are
/// ring-consecutive from the frame's: each further fragment mints exactly one,
/// as that function's up-front mints do, so the two agree on the wire and on
/// the ring whenever there is room throughout.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
fn push_frame<M, Q, P>(
    meta: FrameMeta,
    worst_case: usize,
    body: P,
    tx_sn: &mut M,
    params: &crate::multicast_params::MulticastParams,
    conf: &TxQueueConf,
    queue: &mut Q,
) -> PushOutcome
where
    M: MulticastTxMint + ?Sized,
    Q: MulticastTxQueue + ?Sized,
    P: Fn(&mut crate::tx_buf::TxSink<'_>) -> Result<(), sce_forge_runtime::codec::CodecError>,
{
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
    let mtu = params.batch_size as usize;
    let flags = crate::frame_encode::frame_flags(reliable);
    #[cfg(feature = "transport-tx-lend")]
    {
        // A frame sent whole is at most one batch (past it, it is fragmented),
        // so that is the most a lent slot must hold. NOT the codec's
        // `MAX_ENCODED_BYTES`, which sizes a vector's first reservation and is
        // exceeded by any payload larger than it.
        let want = mtu;
        let mut fill = |slot: &mut crate::tx_buf::SliceTxBuf<'_>| {
            crate::frame_encode::encode_frame_envelope_into(slot, sn, flags, ext_qos, &body).is_ok()
                && crate::tx_buf::TxBuf::len(slot) <= mtu
        };
        if queue.enqueue_lent(priority, reliable, sn, want, &mut fill) {
            return PushOutcome::Pushed;
        }
    }
    let frame = crate::frame_encode::encode_frame_envelope(sn, flags, worst_case, ext_qos, &body);
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
#[cfg(all(feature = "alloc", feature = "codec-push"))]
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
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
pub struct MulticastTxTally {
    #[cfg(feature = "transport-stats")]
    priority: Priority,
    #[cfg(feature = "transport-stats")]
    class: crate::stats::NetworkStatsClass,
}

#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
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

// ─────────── the TX of a build with no allocator ───────────
//
// Fixed-memory step S9e. The emit above frames a queued item into a `Vec<Vec<u8>>`
// of datagrams: a boxed owned message, a vector for the frame, a vector for each
// fragment. A node with no allocator frames the same message into ONE buffer the
// caller lends, a datagram at a time, from the borrowed `Push` over the text and the
// bytes the caller holds ([`crate::lent_push::literal_put`]), and sends each datagram
// before the buffer is written again. The wire is the same: the frame is
// [`crate::frame_encode::encode_frame_envelope_into`] and a fragment is
// [`crate::frame_encode::write_fragment`], the writers the heap emit uses, over the
// same [`FragmentPlan`](crate::frame_encode::FragmentPlan), and the SN walk is the
// emit's (`multicast_frame_or_fragments`), so the two cannot differ in a byte.

/// A `Put` the multicast TX seam of a build with no allocator is offered: the
/// literal keyexpr and the payload as the caller holds them, borrowed for the call
/// that frames them. What `MulticastTxItem::Push` is on the heap profile, with no
/// owned message and no box: nothing here outlives the emit.
#[cfg(all(feature = "codec-push", feature = "transport-tx-lend"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MulticastTxPut<'a> {
    /// The keyexpr, literal (the `id == 0` form, its suffix carried inline).
    pub keyexpr: &'a str,
    /// The payload.
    pub payload: &'a [u8],
    /// Channel selection, as for `MulticastTxItem::Push`: reliable mints on the
    /// reliable ring, best-effort on the other.
    pub reliable: bool,
    /// The QoS band, clamped as the heap emit clamps it (to DEFAULT unless the group
    /// negotiated `is_qos` under `transport-qos`).
    pub priority: Priority,
}

#[cfg(all(feature = "codec-push", feature = "transport-tx-lend"))]
impl<'a> MulticastTxPut<'a> {
    /// A reliable, DEFAULT-band Put: `multicast_put_literal`'s item, borrowed.
    pub const fn literal(keyexpr: &'a str, payload: &'a [u8]) -> Self {
        Self {
            keyexpr,
            payload,
            reliable: true,
            priority: Priority::DEFAULT,
        }
    }
}

/// What the pull seam of a multicast drive loop yields, in the form of the build's
/// profile: the owned, boxed [`MulticastTxItem`] of the heap profile, or a borrowed
/// `MulticastTxPut` on a build with no allocator. The lifetime is the borrow the
/// slot profile's form holds and the heap profile's does not need, so one signature
/// serves both.
#[cfg(any(
    feature = "alloc",
    not(feature = "codec-push"),
    not(feature = "transport-tx-lend")
))]
pub type MulticastTxOffer<'a> = MulticastTxItem;
/// See the heap form of this alias.
#[cfg(all(
    not(feature = "alloc"),
    feature = "codec-push",
    feature = "transport-tx-lend"
))]
pub type MulticastTxOffer<'a> = MulticastTxPut<'a>;

/// Why `multicast_tx_emit_lent` sent nothing.
#[cfg(all(feature = "codec-push", feature = "transport-tx-lend"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastTxRefused {
    /// The frame does not fit the group's batch (or the buffer lent) and this build
    /// cuts no fragment chain: zenoh-pico's "Sending the message required
    /// fragmentation feature that is deactivated". The heap emit passes such a frame
    /// through whatever its size, which a buffer of fixed size cannot.
    NeedsFragmentation,
    /// A datagram of the message does not fit the buffer lent: a fragment's head and
    /// chunk are at most the batch, so the buffer is smaller than the group's batch
    /// budget allows for. Nothing is truncated.
    DatagramTooSmall,
    /// The message does not encode (a keyexpr longer than the codec's text bound).
    Unencodable,
}

/// Frame `put` into the datagram buffer `datagram` and hand each datagram it becomes
/// to `send`, in order: a single `T_MID_FRAME` when it fits the group's batch
/// ([`MulticastParams::batch_size`](crate::multicast_params::MulticastParams::batch_size),
/// held to the buffer's own length), else the `T_MID_FRAGMENT` chain it re-frames
/// into. Answers how many datagrams were sent.
///
/// The no-allocator twin of the heap profile's `multicast_tx_emit`, with the same
/// minting: the frame takes its conduit's next SN, and a chain takes one more for
/// each further fragment, on the SAME conduit, so the ring stays consecutive and the
/// next JOIN beacon advertises the post-chain `next_*`. `send` may borrow the
/// buffer's bytes for the call only: the buffer is written again for the next
/// datagram.
#[cfg(all(feature = "codec-push", feature = "transport-tx-lend"))]
pub fn multicast_tx_emit_lent(
    put: &MulticastTxPut<'_>,
    tx_sn: &mut crate::sn::MulticastTxConduits,
    params: &crate::multicast_params::MulticastParams,
    datagram: &mut [u8],
    send: &mut dyn FnMut(&[u8]),
) -> Result<usize, MulticastTxRefused> {
    use crate::tx_buf::{CappedTxBuf, SliceTxBuf, TxBuf};

    let priority = effective_mcast_priority(put.priority, params.is_qos);
    let ext_qos = frame_ext_qos(priority);
    let reliable = put.reliable;
    let sn = tx_sn.mint(priority, reliable);
    let mtu = core::cmp::min(params.batch_size as usize, datagram.len());
    let flags = crate::frame_encode::frame_flags(reliable);
    let push = crate::lent_push::literal_put(put.keyexpr, put.payload);
    let body = |sink: &mut crate::tx_buf::TxSink<'_>| push.encode(sink);

    // The frame whole, when it fits the batch: the cap makes a refusal mean "past it".
    let whole = {
        let mut buf = SliceTxBuf::new(&mut *datagram);
        let mut capped = CappedTxBuf::new(&mut buf, mtu);
        crate::frame_encode::encode_frame_envelope_into(&mut capped, sn, flags, ext_qos, body)
            .ok()
            .map(|()| TxBuf::len(&capped))
    };
    if let Some(len) = whole {
        send(&datagram[..len]);
        return Ok(1);
    }

    #[cfg(feature = "transport-fragmentation")]
    {
        use crate::frame_encode::{encoded_body_len, write_fragment, FragmentBody, FragmentPlan};
        let encode: &crate::frame_encode::BodyEncoder<'_> = &body;
        let body_len = encoded_body_len(encode).map_err(|_| MulticastTxRefused::Unencodable)?;
        let mut plan = FragmentPlan::new(body_len, mtu, sn, tx_sn.mask(), ext_qos);
        let mut sent = 0usize;
        while let Some(span) = plan.next_span() {
            // The first fragment rides the frame's SN, each further one mints the
            // conduit's next, as `multicast_frame_or_fragments` does.
            if sent > 0 {
                tx_sn.mint(priority, reliable);
            }
            let len = {
                let mut buf = SliceTxBuf::new(&mut *datagram);
                write_fragment(
                    &mut buf,
                    &span,
                    FragmentBody::Encoded(encode),
                    reliable,
                    ext_qos,
                )
                .map_err(|_| MulticastTxRefused::DatagramTooSmall)?;
                TxBuf::len(&buf)
            };
            send(&datagram[..len]);
            sent += 1;
        }
        Ok(sent)
    }
    #[cfg(not(feature = "transport-fragmentation"))]
    {
        Err(MulticastTxRefused::NeedsFragmentation)
    }
}

/// Emit one offer of a pull seam: the heap profile's `multicast_tx_emit` over the
/// owned item, or `multicast_tx_emit_lent` over a lent `Put`, whichever the
/// build's [`MulticastTxOffer`] is, handing each datagram to `send`. Answers how many
/// datagrams went out (none for a refused offer, which a best-effort multicast TX
/// has no one to tell). `scratch` is the datagram buffer of the lent form and is not
/// touched by the heap one.
///
/// One call for both profiles, so a drive loop carries no `cfg` at its TX drain, and
/// a build with no TX body codec, whose offer cannot be made, matches on an empty
/// type.
pub fn multicast_tx_emit_offer(
    offer: MulticastTxOffer<'_>,
    tx_sn: &mut crate::sn::MulticastTxConduits,
    params: &crate::multicast_params::MulticastParams,
    scratch: &mut [u8],
    send: &mut dyn FnMut(&[u8]),
) -> usize {
    #[cfg(all(
        feature = "alloc",
        any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "liveliness-token"
        )
    ))]
    {
        let _ = scratch;
        let frames = multicast_tx_emit(offer, tx_sn, params);
        for datagram in &frames.datagrams {
            send(datagram);
        }
        frames.datagrams.len()
    }
    #[cfg(all(
        not(feature = "alloc"),
        feature = "codec-push",
        feature = "transport-tx-lend"
    ))]
    {
        multicast_tx_emit_lent(&offer, tx_sn, params, scratch, send).unwrap_or(0)
    }
    #[cfg(not(any(
        all(
            feature = "alloc",
            any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "liveliness-token"
            )
        ),
        all(
            not(feature = "alloc"),
            feature = "codec-push",
            feature = "transport-tx-lend"
        )
    )))]
    {
        let _ = (tx_sn, params, scratch, send);
        match offer {}
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
            zid: crate::multicast_params::zid_vec(&[1, 2, 3, 4]),
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
            zid: crate::multicast_params::zid_vec(&[1, 2, 3, 4]),
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

    /// R2937 — a producer that holds one conduit pushes against it alone: the
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

    /// R2937 — the control of the one above: a push whose band is not the one
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

// R3264 — the multicast push into a queue that LENDS: the datagram is encoded
// straight into the lent slot, the bytes and the SN walk are the heap path's,
// and every way the lend cannot take a frame falls back to the heap.
#[cfg(all(test, feature = "codec-push", feature = "transport-tx-lend"))]
mod lend_tests {
    use super::*;
    use crate::multicast_params::MulticastParams;
    use crate::sn::{mask_from_res, MulticastTxConduits};
    use crate::tx_buf::{SliceTxBuf, TxBuf};
    use crate::WhatAmI;

    fn params(batch_size: u16, is_qos: bool) -> MulticastParams {
        MulticastParams {
            version: 0x09,
            whatami: WhatAmI::Peer,
            zid: crate::multicast_params::zid_vec(&[1, 2, 3, 4]),
            lease_ms: 5_000,
            join_interval_ms: 50,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size,
            is_qos,
            tx_queue: TxQueueConf::default(),
        }
    }

    /// A queue that lends from two slot sizes, small first, as the AP pipeline
    /// does, and records what went where.
    struct Lending {
        small: usize,
        large: usize,
        /// Datagrams that arrived through a lent slot: `(slot size, bytes, sn)`.
        lent: Vec<(usize, Vec<u8>, u64)>,
        /// Datagrams that arrived as vectors.
        heap: Vec<(Vec<u8>, u64)>,
        offers: usize,
        refused: usize,
    }

    impl Lending {
        fn new(small: usize, large: usize) -> Self {
            Self {
                small,
                large,
                lent: Vec::new(),
                heap: Vec::new(),
                offers: 0,
                refused: 0,
            }
        }
    }

    impl MulticastTxQueue for Lending {
        fn wait_for_room(&mut self, _priority: Priority, _wait: RoomWait) -> RoomAnswer {
            RoomAnswer::at_once(LinkRoom::Free)
        }

        fn enqueue(&mut self, datagram: MulticastTxDatagram) {
            self.heap.push((datagram.bytes, datagram.sn));
        }

        fn enqueue_lent(
            &mut self,
            _priority: Priority,
            _reliable: bool,
            sn: u64,
            want: usize,
            fill: &mut dyn FnMut(&mut SliceTxBuf<'_>) -> bool,
        ) -> bool {
            for size in [self.small.min(want), self.large.min(want)] {
                self.offers += 1;
                let mut storage = alloc::vec![0u8; size];
                let mut slot = SliceTxBuf::new(&mut storage);
                if fill(&mut slot) {
                    let bytes = slot.as_slice().to_vec();
                    self.lent.push((size, bytes, sn));
                    return true;
                }
                self.refused += 1;
            }
            false
        }
    }

    fn put(payload: &[u8], priority: Priority) -> MulticastTxItem {
        MulticastTxItem::Push {
            push: Box::new(crate::push_build::build_push_literal("k/lent", payload).unwrap()),
            reliable: true,
            priority,
        }
    }

    /// The heap path's frame for the same item: the queue-less emit.
    fn emitted(item: MulticastTxItem, params: &MulticastParams) -> Vec<Vec<u8>> {
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        multicast_tx_emit(item, &mut tx, params).datagrams
    }

    /// A push is encoded INTO the lent slot, and the slot holds exactly the
    /// frame the heap path builds: with and without a QoS band.
    #[test]
    fn a_lent_datagram_is_the_frame_the_heap_path_builds() {
        for (is_qos, priority) in [(false, Priority::DEFAULT), (true, Priority::RealTime)] {
            let params = params(8_192, is_qos);
            let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
            let mut queue = Lending::new(1_472, 65_600);
            let outcome = multicast_tx_push(
                put(b"payload", priority),
                &mut tx,
                &params,
                &TxQueueConf::default(),
                &mut queue,
            );
            assert_eq!(outcome, PushOutcome::Pushed);
            assert!(queue.heap.is_empty(), "nothing took the heap path");
            assert_eq!(queue.lent.len(), 1);
            let (size, bytes, sn) = &queue.lent[0];
            assert_eq!(*size, 1_472, "a small frame takes the small slot");
            assert_eq!(*sn, 0);
            assert_eq!(
                alloc::vec![bytes.clone()],
                emitted(put(b"payload", priority), &params),
                "qos {is_qos}"
            );
        }
    }

    /// A frame past the small slot is refused there and encoded into the
    /// larger one, the same bytes.
    #[test]
    fn a_frame_past_the_small_slot_takes_the_larger_one() {
        let params = params(8_192, false);
        let payload = [0x5Au8; 3_000];
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Lending::new(1_472, 65_600);
        multicast_tx_push(
            put(&payload, Priority::DEFAULT),
            &mut tx,
            &params,
            &TxQueueConf::default(),
            &mut queue,
        );
        assert_eq!((queue.offers, queue.refused), (2, 1));
        assert_eq!(queue.lent.len(), 1);
        assert!(queue.lent[0].0 > 1_472);
        assert_eq!(
            alloc::vec![queue.lent[0].1.clone()],
            emitted(put(&payload, Priority::DEFAULT), &params)
        );
    }

    /// A frame past the group's batch is NOT sent from a slot: every offer is
    /// refused and the message is fragmented from the heap, the very chain the
    /// emit returns, its SNs ring-consecutive from the one minted for the lend.
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn a_frame_past_the_batch_is_fragmented_from_the_heap() {
        let params = params(256, false);
        let payload = [0xA5u8; 1_000];
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Lending::new(1_472, 65_600);
        multicast_tx_push(
            put(&payload, Priority::DEFAULT),
            &mut tx,
            &params,
            &TxQueueConf::default(),
            &mut queue,
        );
        assert!(
            queue.lent.is_empty(),
            "no slot holds a frame past the batch"
        );
        assert!(queue.refused >= 1);
        let chain: Vec<Vec<u8>> = queue.heap.iter().map(|(b, _)| b.clone()).collect();
        assert!(chain.len() > 2, "the message fragments");
        assert_eq!(chain, emitted(put(&payload, Priority::DEFAULT), &params));
        let sns: Vec<u64> = queue.heap.iter().map(|(_, sn)| *sn).collect();
        assert_eq!(sns, (0..chain.len() as u64).collect::<Vec<_>>());
    }

    /// The SN walk through the lend is the heap path's: consecutive pushes mint
    /// consecutive SNs, each carried by its own lent slot.
    #[test]
    fn consecutive_lent_pushes_carry_consecutive_sequence_numbers() {
        let params = params(8_192, false);
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Lending::new(1_472, 65_600);
        for _ in 0..3 {
            multicast_tx_push(
                put(b"v", Priority::DEFAULT),
                &mut tx,
                &params,
                &TxQueueConf::default(),
                &mut queue,
            );
        }
        let sns: Vec<u64> = queue.lent.iter().map(|(_, _, sn)| *sn).collect();
        assert_eq!(sns, [0, 1, 2]);
        assert_eq!(tx.advertise_default().next_reliable, 3);
    }
}

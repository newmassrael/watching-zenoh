// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
    /// A query over multicast (`z_get` / `z_querier_get` on a group): the `Request(Query)` a
    /// multicast session sends to every peer of the group, which each answers with its replies and
    /// one `ResponseFinal` (zenoh-pico's `_z_query` sends it through `_z_send_n_msg`, whose
    /// multicast branch writes it to the group, `vendor/zenoh-pico/src/transport/common/tx.c` @
    /// `_z_transport_tx_send_n_msg(&zn->_tp._transport._multicast._common, z_msg, reliability, cong_ctrl, NULL);`).
    /// Reliable, as the unicast query is: a dropped query leaves the querier waiting for finals no
    /// peer owes.
    ///
    /// Gated on `codec-push` beside `codec-request` because a multicast session sends only
    /// through the producer `codec-push` provides; a build with the query codec and no push codec
    /// has no group to send it on.
    #[cfg(all(feature = "alloc", feature = "codec-push", feature = "codec-request"))]
    Request {
        /// The built `Request(Query)`, boxed to bound the enum size.
        request: Box<crate::wire::RequestOwned>,
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
        request_id: crate::wire_id::RequestId,
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
    #[cfg(all(
        feature = "alloc",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    ))]
    DeclareReply {
        /// The built `Declare` reply (a `DeclToken` for a held token, or the
        /// terminating `DeclFinal`), already owned via `Declare::try_into_owned`.
        /// Boxed (R311mb) to bound the enum size.
        declare: Box<crate::transport_profile::owned::DeclareOwned>,
    },
    /// Open-debt item 913 — a declaration the session ANNOUNCES on the group, answering no
    /// interest: zenoh announces a session's subscriber on each group it holds
    /// (`zenoh/src/net/routing/hat/peer/pubsub.rs` @
    /// `if we have a multicast group, we use it to propagate subscribers to upstream gateways.`).
    /// Framed, sent and counted as a
    /// `MulticastTxItem::DeclareReply` is (`declare_frame_meta`); the two
    /// differ in what produced them, an interest or the session.
    // A group session sends through its producer only under `codec-push`, so the variant is
    // built where both are.
    #[cfg(all(feature = "alloc", feature = "codec-declare", feature = "codec-push"))]
    Declare {
        /// The built `Declare`, boxed to bound the enum size.
        declare: Box<crate::transport_profile::owned::DeclareOwned>,
    },
    /// Open-debt item 913 — an `Interest` the session asks the group: zenoh-pico at
    /// `Z_FEATURE_MULTICAST_DECLARATIONS=1` asks its group for the members' keyexprs when it
    /// opens and for their subscribers or queryables when an entity's write filter is made, over
    /// the multicast transport it holds (`vendor/zenoh-pico/src/net/primitives.c` @
    /// `|| (zn->_tp._type == _Z_TRANSPORT_MULTICAST_TYPE)`). Framed as a `Declare` is
    /// (`interest_frame_meta`): reliable and DEFAULT-band, as pico sends it with
    /// `Z_RELIABILITY_RELIABLE` and no QoS of its own.
    #[cfg(all(feature = "alloc", feature = "codec-push"))]
    Interest {
        /// The built `Interest`, boxed to bound the enum size.
        interest: Box<crate::transport_profile::owned::InterestOwned>,
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
    /// MCU loop's, the collecting one behind `multicast_tx_emit`). A push asks
    /// only under `transport-tx-lend`; a queue may offer its slots in any build.
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
struct UnboundedCollect(Vec<Vec<u8>>);

#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
pub fn multicast_tx_emit(
    item: MulticastTxItem,
    tx_sn: &mut crate::sn::MulticastTxConduits,
    params: &crate::multicast_params::MulticastParams,
) -> MulticastTxFrames {
    let reliable = multicast_tx_reliable(&item);
    let mut collect = UnboundedCollect(Vec::new());
    // Always room, so never `Congested` and the waits are never spent; the queue is the one the
    // group's snapshots make, as every queue a machine builds is.
    let _ = multicast_tx_push(
        item,
        tx_sn,
        params,
        &TxQueueConf::of_snapshot(&params.policy, &params.limits),
        &mut collect,
    );
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
fn multicast_tx_reliable(item: &MulticastTxItem) -> bool {
    match item {
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Push { reliable, .. } => *reliable,
        #[cfg(all(feature = "codec-push", feature = "codec-request"))]
        MulticastTxItem::Request { .. } => true,
        #[cfg(feature = "codec-response")]
        MulticastTxItem::Response { .. } => true,
        #[cfg(feature = "codec-response-final")]
        MulticastTxItem::ResponseFinal { .. } => true,
        #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
        MulticastTxItem::DeclareReply { .. } => true,
        #[cfg(all(feature = "codec-declare", feature = "codec-push"))]
        MulticastTxItem::Declare { .. } => true,
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Interest { .. } => true,
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
    multicast_tx_push_in(item, tx_sn, params, conf, queue, None)
}

/// [`multicast_tx_push`] inside a batch window (zenoh-pico `zp_batch_start` on a multicast
/// transport): the message is appended to `window`, its conduit's open frame, when the frame is
/// of the message's reliability and the message fits behind it, and spends no sequence number;
/// otherwise the open frame is put on `queue` and the message opens the next one, asking for
/// room and taking its SN as an unbatched push does. The frame stays open, and leaves when it
/// overflows, when an express message joins it, or when the window is flushed
/// ([`MulticastBatch::flush`]), as zenoh-pico's common transmit batches
/// (`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(`).
///
/// A message past the group's batch on its own is not held: the open frame leaves first and
/// the message leaves as the fragment chain an unbatched push sends. A window frame is built on
/// the heap and never in a slot the queue lends, since a lent slot is the queue's at once.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
pub fn multicast_tx_push_batched<M, Q>(
    item: MulticastTxItem,
    tx_sn: &mut M,
    params: &crate::multicast_params::MulticastParams,
    conf: &TxQueueConf,
    queue: &mut Q,
    window: &mut MulticastBatch,
) -> PushOutcome
where
    M: MulticastTxMint + ?Sized,
    Q: MulticastTxQueue + ?Sized,
{
    multicast_tx_push_in(item, tx_sn, params, conf, queue, Some(window))
}

/// A message a group's producer pushes for the call without owning it: the network message's
/// own QoS, the channel it rides, the most its body encodes to, and the encoder that writes the
/// body where the frame is built. A message a writer writes from borrowed parts (a query's
/// `lent_request::RequestWriter`) is pushed as this and is never an owned message, so it costs
/// no allocation of its own.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
#[derive(Clone, Copy)]
pub struct MulticastTxEncoded<'a> {
    /// How the message is framed: its band, channel, congestion control and express flag.
    pub framing: MulticastTxFraming,
    /// The most the body encodes to.
    pub size: usize,
    /// The encoder of the network message the frame carries.
    pub body: &'a crate::frame_encode::BodyEncoder<'a>,
    /// What the network counters take of the message once it is pushed: its own band and its
    /// class, read off the parts it is written from as the owned message of the same bytes is read
    /// (`multicast_tx_stats_class`).
    pub tally: MulticastTxTally,
}

/// How a message lent for the call is framed onto a group, read as its owned form is
/// ([`frame_meta`]): the three ways a group's messages take their band.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastTxFraming {
    /// A message whose own `ext_qos` names its band: a query, a reply.
    OwnBand {
        /// The message's `ext_qos`.
        qos: crate::sample::QosLevel,
        /// The channel: the reliable ring, or the best-effort one.
        reliable: bool,
    },
    /// A publication: the band its publisher chose, and its congestion control and express flag
    /// those of its own `ext_qos`.
    Publication {
        /// The publication's `ext_qos`.
        qos: crate::sample::QosLevel,
        /// The channel.
        reliable: bool,
        /// The band its publisher chose.
        priority: Priority,
    },
    /// A declaration or an interest: the DEFAULT band and no frame `ext_qos`, reliable, and
    /// droppable as its own `ext_qos` says.
    Control {
        /// The message's `ext_qos`.
        qos: crate::sample::QosLevel,
    },
}

#[cfg(all(feature = "alloc", feature = "codec-push"))]
impl MulticastTxFraming {
    fn meta(self, params: &crate::multicast_params::MulticastParams) -> FrameMeta {
        match self {
            Self::OwnBand { qos, reliable } => qos_frame_meta(qos, reliable, params),
            Self::Publication {
                qos,
                reliable,
                priority,
            } => publication_frame_meta(qos, reliable, priority, params),
            Self::Control { qos } => control_frame_meta(qos),
        }
    }
}

/// How a publication is framed: the band its publisher chose, clamped as every message's is, and
/// its congestion control and express flag those of its own `ext_qos`.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
fn publication_frame_meta(
    qos: crate::sample::QosLevel,
    reliable: bool,
    priority: Priority,
    params: &crate::multicast_params::MulticastParams,
) -> FrameMeta {
    // R311y227 — clamp the app / routing band to DEFAULT unless the group negotiated `is_qos`
    // (else a non-qos / pico receiver bails "Unknown priority"). Under `transport-qos` on a qos
    // group the clamped band selects the per-priority TX conduit AND rides the frame `ext_qos`.
    let eff = effective_mcast_priority(priority, params.is_qos);
    FrameMeta {
        priority: eff,
        ext_qos: frame_ext_qos(eff),
        reliable,
        droppable: is_droppable(reliable, qos.congestion()),
        express: qos.is_express(),
    }
}

/// How a declaration or an interest is framed: DEFAULT-band, no frame `ext_qos`, reliable, and
/// droppable as its own `ext_qos` says.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
fn control_frame_meta(qos: crate::sample::QosLevel) -> FrameMeta {
    FrameMeta {
        priority: Priority::DEFAULT,
        ext_qos: None,
        reliable: true,
        droppable: is_droppable(true, qos.congestion()),
        express: false,
    }
}

/// What a push of a message with `qos` on the channel `reliable` onto a group of `params` must
/// know besides its bytes: the band its own `ext_qos` names clamped as every message's is, the
/// frame's `ext_qos`, and whether it may be dropped. The one reading of such a message, owned or
/// lent.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
fn qos_frame_meta(
    qos: crate::sample::QosLevel,
    reliable: bool,
    params: &crate::multicast_params::MulticastParams,
) -> FrameMeta {
    let eff = effective_mcast_priority(qos.priority(), params.is_qos);
    FrameMeta {
        priority: eff,
        ext_qos: frame_ext_qos(eff),
        reliable,
        droppable: is_droppable(reliable, qos.congestion()),
        express: qos.is_express(),
    }
}

/// The conduit a push of the lent `message` onto a group of `params` mints on, as
/// [`multicast_tx_conduit`] answers for an owned one.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub fn multicast_tx_encoded_conduit(
    message: &MulticastTxEncoded<'_>,
    params: &crate::multicast_params::MulticastParams,
) -> Priority {
    message.framing.meta(params).priority
}

/// [`multicast_tx_push`] (or [`multicast_tx_push_batched`] inside a window) of a message lent for
/// the call ([`MulticastTxEncoded`]): the same walk, its body written by its encoder where the
/// frame is built.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub fn multicast_tx_push_encoded<M, Q>(
    message: &MulticastTxEncoded<'_>,
    tx_sn: &mut M,
    params: &crate::multicast_params::MulticastParams,
    conf: &TxQueueConf,
    queue: &mut Q,
    window: Option<&mut MulticastBatch>,
) -> PushOutcome
where
    M: MulticastTxMint + ?Sized,
    Q: MulticastTxQueue + ?Sized,
{
    push_frame(
        FramedBody {
            meta: message.framing.meta(params),
            worst_case: message.size,
            body: message.body,
        },
        tx_sn,
        params,
        conf,
        queue,
        window,
    )
}

/// How a message is framed onto a group, read off it once: the conduit it mints on, the frame's
/// `ext_qos`, its channel, whether it may be dropped and whether it is express. A group that keeps
/// a message's encoded body until a sequence number can be minted for it keeps this beside the
/// bytes, so the frame it is put in later is the one it would have been put in at once.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
#[derive(Clone, Copy)]
pub struct MulticastTxMeta(FrameMeta);

#[cfg(all(feature = "alloc", feature = "codec-push"))]
impl MulticastTxMeta {
    /// How the lent `message` is framed onto a group of `params`.
    pub fn of_encoded(
        message: &MulticastTxEncoded<'_>,
        params: &crate::multicast_params::MulticastParams,
    ) -> Self {
        Self(message.framing.meta(params))
    }

    /// How `item` is framed onto a group of `params`.
    pub fn of_item(
        item: &MulticastTxItem,
        params: &crate::multicast_params::MulticastParams,
    ) -> Self {
        Self(frame_meta(item, params))
    }

    /// How a reply that goes out with `qos` is framed onto a group of `params`: on the reliable
    /// channel, on the band its QoS names. The one reading of a reply's framing, of its owned
    /// record ([`MulticastTxReply::meta`]) and of its parts.
    #[cfg(feature = "codec-response")]
    pub fn of_reply(
        qos: crate::sample::QosLevel,
        params: &crate::multicast_params::MulticastParams,
    ) -> Self {
        Self(qos_frame_meta(qos, true, params))
    }

    /// The conduit the message mints on: the lane its datagrams take.
    pub fn conduit(self) -> Priority {
        self.0.priority
    }
}

/// A reply a group's dispatch hands its backing for the call
/// ([`MulticastReplyEnqueue::enqueue_reply`](crate::multicast_reply_sink::MulticastReplyEnqueue::enqueue_reply)):
/// the message borrowed from where it was built. A backing that keeps its replies owned copies it
/// ([`Self::to_item`]); one that keeps them encoded writes it from where it lies.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "liveliness-token",
        feature = "declare-subscriber"
    )
))]
#[derive(Clone, Copy)]
pub enum MulticastTxReply<'a> {
    /// A queryable's `Response` to a member's query.
    #[cfg(feature = "codec-response")]
    Response(&'a crate::wire::ResponseOwned),
    /// A `Declare` that answers a member's interest.
    #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
    DeclareReply(&'a crate::transport_profile::owned::DeclareOwned),
}

#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "liveliness-token",
        feature = "declare-subscriber"
    )
))]
impl MulticastTxReply<'_> {
    /// What the network counters take of the reply once it is pushed, as [`MulticastTxTally::of`]
    /// reads its owned item: its own band and its class.
    pub fn tally(self) -> MulticastTxTally {
        #[cfg(feature = "transport-stats")]
        {
            match self {
                #[cfg(feature = "codec-response")]
                Self::Response(response) => MulticastTxTally::new(
                    crate::declare_ext_qos::read_response_qos(response).priority(),
                    crate::network_message::response_stats_class(response, |_| None),
                ),
                #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
                Self::DeclareReply(declare) => MulticastTxTally::new(
                    crate::declare_ext_qos::read_declare_qos(declare).priority(),
                    crate::stats::NetworkStatsClass::control(crate::stats::MessageLabel::Declare),
                ),
            }
        }
        #[cfg(not(feature = "transport-stats"))]
        {
            let _ = self;
            MulticastTxTally::new(Priority::DEFAULT, crate::stats::NetworkStatsClass::unread())
        }
    }

    /// The reply as the owned item a backing that keeps owned replies queues, copied.
    pub fn to_item(self) -> MulticastTxItem {
        match self {
            #[cfg(feature = "codec-response")]
            Self::Response(response) => MulticastTxItem::Response {
                response: Box::new(response.clone()),
            },
            #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
            Self::DeclareReply(declare) => MulticastTxItem::DeclareReply {
                declare: Box::new(declare.clone()),
            },
        }
    }

    /// The most bytes the reply's network message encodes to, as [`multicast_tx_bytes`] counts
    /// the owned item.
    pub fn bytes(self) -> usize {
        match self {
            #[cfg(feature = "codec-response")]
            Self::Response(response) => wz_codecs::response::ResponseWire::measure(response).len(),
            #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
            Self::DeclareReply(declare) => wz_codecs::declare::DeclareWire::measure(declare).len(),
        }
    }

    /// How the reply is framed onto a group of `params`, as [`MulticastTxMeta::of_item`] reads the
    /// owned item.
    #[cfg(feature = "codec-push")]
    pub fn meta(self, params: &crate::multicast_params::MulticastParams) -> MulticastTxMeta {
        match self {
            #[cfg(feature = "codec-response")]
            Self::Response(response) => MulticastTxMeta::of_reply(
                crate::declare_ext_qos::read_response_qos(response),
                params,
            ),
            #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
            Self::DeclareReply(declare) => {
                let _ = params;
                MulticastTxMeta(declare_frame_meta(declare))
            }
        }
    }

    /// `f` handed the encoder of the reply's network message.
    #[cfg(feature = "codec-push")]
    pub fn with_body<R>(self, f: impl FnOnce(&crate::frame_encode::BodyEncoder<'_>) -> R) -> R {
        match self {
            #[cfg(feature = "codec-response")]
            Self::Response(response) => {
                f(&|sink: &mut crate::tx_buf::TxSink<'_>| response.encode(sink))
            }
            #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
            Self::DeclareReply(declare) => {
                f(&|sink: &mut crate::tx_buf::TxSink<'_>| declare.encode(sink))
            }
        }
    }
}

/// `f` handed the encoder of `item`'s network message: what a group that keeps the message's
/// body until its sequence number can be minted encodes it with.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub fn multicast_tx_item_body<R>(
    item: &MulticastTxItem,
    f: impl FnOnce(&crate::frame_encode::BodyEncoder<'_>) -> R,
) -> R {
    match item {
        MulticastTxItem::Push { push, .. } => f(&crate::frame_encode::push_body(push)),
        #[cfg(feature = "codec-request")]
        MulticastTxItem::Request { request } => {
            f(&|sink: &mut crate::tx_buf::TxSink<'_>| request.encode(sink))
        }
        #[cfg(feature = "codec-response")]
        MulticastTxItem::Response { response } => {
            f(&|sink: &mut crate::tx_buf::TxSink<'_>| response.encode(sink))
        }
        #[cfg(feature = "codec-response-final")]
        MulticastTxItem::ResponseFinal { request_id, qos } => {
            let response_final =
                crate::response_final_build::build_response_final(*request_id, *qos);
            // Named, so the encoder that borrows the message is let go before the message is.
            let body = |sink: &mut crate::tx_buf::TxSink<'_>| response_final.encode(sink);
            f(&body)
        }
        #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
        MulticastTxItem::DeclareReply { declare } => {
            f(&|sink: &mut crate::tx_buf::TxSink<'_>| declare.encode(sink))
        }
        #[cfg(feature = "codec-declare")]
        MulticastTxItem::Declare { declare } => {
            f(&|sink: &mut crate::tx_buf::TxSink<'_>| declare.encode(sink))
        }
        MulticastTxItem::Interest { interest } => {
            f(&|sink: &mut crate::tx_buf::TxSink<'_>| interest.encode(sink))
        }
    }
}

/// Encode `body` into `out`: the length written, or `None` when the encoder refuses the message
/// or `out` is too short for it.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub fn multicast_tx_encode_into(
    body: &crate::frame_encode::BodyEncoder<'_>,
    out: &mut [u8],
) -> Option<usize> {
    #[cfg(feature = "transport-tx-lend")]
    {
        let mut slot = crate::tx_buf::SliceTxBuf::new(out);
        body(&mut crate::tx_buf::TxSink::new(&mut slot)).ok()?;
        Some(crate::tx_buf::TxBuf::len(&slot))
    }
    // A build whose encoders write a vector has no other buffer to write into: the bytes are
    // copied out of one.
    #[cfg(not(feature = "transport-tx-lend"))]
    {
        let mut bytes = Vec::new();
        body(&mut crate::tx_buf::TxSink::new(&mut bytes)).ok()?;
        out.get_mut(..bytes.len())?.copy_from_slice(&bytes);
        Some(bytes.len())
    }
}

/// [`multicast_tx_push_encoded`] of a message whose framing was read off it before
/// (`meta`) and whose body is `body`, at most `size` bytes.
/// The group's own queue configuration (`params.tx_queue`) paces it, as it paces
/// [`multicast_tx_push_staged`].
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub fn multicast_tx_push_meta<M, Q>(
    meta: MulticastTxMeta,
    size: usize,
    body: &crate::frame_encode::BodyEncoder<'_>,
    tx_sn: &mut M,
    params: &crate::multicast_params::MulticastParams,
    queue: &mut Q,
    window: Option<&mut MulticastBatch>,
) -> PushOutcome
where
    M: MulticastTxMint + ?Sized,
    Q: MulticastTxQueue + ?Sized,
{
    push_frame(
        FramedBody {
            meta: meta.0,
            worst_case: size,
            body,
        },
        tx_sn,
        params,
        &params.tx_queue,
        queue,
        window,
    )
}

/// [`multicast_tx_push_meta`] of a message whose body was encoded before, into `staged`
/// ([`multicast_tx_encode_into`]): the bytes are the body the frame carries.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub fn multicast_tx_push_staged<M, Q>(
    meta: MulticastTxMeta,
    staged: &[u8],
    tx_sn: &mut M,
    params: &crate::multicast_params::MulticastParams,
    queue: &mut Q,
    window: Option<&mut MulticastBatch>,
) -> PushOutcome
where
    M: MulticastTxMint + ?Sized,
    Q: MulticastTxQueue + ?Sized,
{
    use sce_forge_runtime::codec::SceSink;
    let body = |sink: &mut crate::tx_buf::TxSink<'_>| sink.write_bytes(staged);
    push_frame(
        FramedBody {
            meta: meta.0,
            worst_case: staged.len(),
            body,
        },
        tx_sn,
        params,
        &params.tx_queue,
        queue,
        window,
    )
}

/// The bytes `body` encodes to, or `None` when its encoder refuses the message.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
fn encoded_size(body: &crate::frame_encode::BodyEncoder<'_>) -> Option<usize> {
    #[cfg(feature = "transport-tx-lend")]
    let size = crate::tx_buf::encoded_len(body);
    // A build whose encoders write a vector counts by writing one.
    #[cfg(not(feature = "transport-tx-lend"))]
    let size = {
        let mut bytes = Vec::new();
        match body(&mut crate::tx_buf::TxSink::new(&mut bytes)) {
            Ok(()) => bytes.len(),
            Err(_) => 0,
        }
    };
    (size > 0).then_some(size)
}

/// `f` handed `declaration`, a declaration written from its parts
/// ([`crate::lent_control`]), as a message lent for the call: framed as the owned `Declare` is.
/// `None` when its encoder refuses it, with `f` not called.
#[cfg(all(feature = "alloc", feature = "codec-push", feature = "codec-declare"))]
pub fn multicast_tx_declaration<S, R>(
    declaration: &S,
    f: impl FnOnce(&MulticastTxEncoded<'_>) -> R,
) -> Option<R>
where
    S: wz_codecs::declare::DeclareSource,
{
    let body = |sink: &mut crate::tx_buf::TxSink<'_>| {
        wz_codecs::declare::DeclareWire::encode_source(declaration, sink)
    };
    let size = encoded_size(&body)?;
    let qos = crate::declare_ext_qos::QOS_DECLARE;
    Some(f(&MulticastTxEncoded {
        framing: MulticastTxFraming::Control { qos },
        size,
        body: &body,
        tally: MulticastTxTally::new(
            qos.priority(),
            crate::stats::NetworkStatsClass::control(crate::stats::MessageLabel::Declare),
        ),
    }))
}

/// `f` handed `interest`, an interest written from its parts ([`crate::lent_control`]), as a
/// message lent for the call: framed as the owned `Interest` is. `None` when its encoder refuses
/// it, with `f` not called.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub fn multicast_tx_interest<R>(
    interest: &wz_codecs::lent::Interest<'_>,
    f: impl FnOnce(&MulticastTxEncoded<'_>) -> R,
) -> Option<R> {
    let body = |sink: &mut crate::tx_buf::TxSink<'_>| interest.encode(sink);
    let size = encoded_size(&body)?;
    Some(f(&MulticastTxEncoded {
        // An interest written from its parts carries no `ext_qos` (`lent_control::interest_exact`).
        framing: MulticastTxFraming::Control {
            qos: crate::sample::QosLevel::DEFAULT,
        },
        size,
        body: &body,
        tally: MulticastTxTally::new(
            Priority::DEFAULT,
            crate::stats::NetworkStatsClass::control(crate::stats::MessageLabel::Interest),
        ),
    }))
}

/// `f` handed the answer to a member's interest in liveliness tokens for one held token, written
/// from the borrowed reply ([`crate::declare::local_token::build_token_reply`]) as a message lent
/// for the call: framed as the owned reply is, which carries no `ext_qos`. `None` when its encoder
/// refuses it (a keyexpr past the protocol's bound), with `f` not called.
///
/// The reply is built again inside its encoder, as the session with no allocator writes it to its
/// link, so the borrowed message is on the stack only while it is counted or written.
#[cfg(all(
    feature = "alloc",
    feature = "codec-push",
    feature = "liveliness-token"
))]
pub fn multicast_tx_token_reply<R>(
    token_id: u64,
    keyexpr: &str,
    interest_id: u64,
    f: impl FnOnce(&MulticastTxEncoded<'_>) -> R,
) -> Option<R> {
    let body = |sink: &mut crate::tx_buf::TxSink<'_>| {
        crate::declare::local_token::build_token_reply(token_id, keyexpr, interest_id)?.encode(sink)
    };
    let size = encoded_size(&body)?;
    Some(f(&MulticastTxEncoded {
        framing: MulticastTxFraming::Control {
            qos: crate::sample::QosLevel::DEFAULT,
        },
        size,
        body: &body,
        tally: MulticastTxTally::new(
            Priority::DEFAULT,
            crate::stats::NetworkStatsClass::control(crate::stats::MessageLabel::Declare),
        ),
    }))
}

/// `f` handed the get `writer` writes from its borrowed parts
/// ([`crate::lent_request::RequestWriter`]), as a message lent for the call: framed as the owned
/// `Request` is, on the band its own `ext_qos` (`qos`) names, reliable. `None` when its writer
/// refuses it, with `f` not called.
#[cfg(all(feature = "alloc", feature = "codec-push", feature = "codec-request"))]
pub fn multicast_tx_request<R>(
    writer: &crate::lent_request::RequestWriter<'_>,
    qos: crate::sample::QosLevel,
    f: impl FnOnce(&MulticastTxEncoded<'_>) -> R,
) -> Option<R> {
    let body = |sink: &mut crate::tx_buf::TxSink<'_>| writer.encode(sink);
    let size = encoded_size(&body)?;
    #[cfg(feature = "transport-stats")]
    let class = crate::network_message::get_stats_class(writer, |_| None);
    #[cfg(not(feature = "transport-stats"))]
    let class = crate::stats::NetworkStatsClass::unread();
    Some(f(&MulticastTxEncoded {
        framing: MulticastTxFraming::OwnBand {
            qos,
            reliable: true,
        },
        size,
        body: &body,
        tally: MulticastTxTally::new(qos.priority(), class),
    }))
}

/// [`crate::declare_build::build_group_announcement`] written from its parts and handed to `f` as a
/// message lent for the call ([`multicast_tx_declaration`]); the builder's errors, and
/// `FeatureDisabled` for a kind this build has no declaration plane of.
#[cfg(all(feature = "alloc", feature = "codec-push", feature = "codec-declare"))]
pub fn multicast_tx_group_announcement<R>(
    what: crate::declare_form::GroupDeclaration,
    id: u64,
    key: crate::declare_form::GroupKey<'_>,
    f: impl FnOnce(&MulticastTxEncoded<'_>) -> R,
) -> Result<R, crate::send_wire_error::SendWireError> {
    use crate::declare_form::GroupDeclaration;
    use crate::send_wire_error::SendWireError;
    let crate::declare_form::GroupKey { mapping_id, suffix } = key;
    let refused = SendWireError::Codec(sce_forge_runtime::codec::CodecError::LengthOutOfRange);
    match what {
        #[cfg(feature = "declare-subscriber")]
        GroupDeclaration::Subscriber => {
            let declaration = crate::lent_control::subscriber_declaration(id, mapping_id, suffix)
                .map_err(SendWireError::Codec)?;
            multicast_tx_declaration(&declaration, f).ok_or(refused)
        }
        #[cfg(feature = "declare-queryable")]
        GroupDeclaration::Queryable { complete } => {
            let declaration = crate::lent_control::queryable_declaration(
                id,
                mapping_id,
                suffix,
                crate::queryable_info::QueryableInfo::local(complete),
            )
            .map_err(SendWireError::Codec)?;
            multicast_tx_declaration(&declaration, f).ok_or(refused)
        }
        #[cfg(feature = "liveliness-token")]
        GroupDeclaration::Token => {
            let declaration = crate::lent_control::token_declaration(id, mapping_id, suffix)
                .map_err(SendWireError::Codec)?;
            multicast_tx_declaration(&declaration, f).ok_or(refused)
        }
        #[cfg(not(all(
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "liveliness-token"
        )))]
        _ => {
            let _ = (id, mapping_id, suffix, f, refused);
            Err(SendWireError::FeatureDisabled)
        }
    }
}

/// [`crate::declare_build::build_group_retraction`] written from its parts, its key's
/// `ext_keyexpr` body on the stack, and handed to `f` as a message lent for the call; refused
/// with `LengthOutOfRange` for a key past the build's longest, and `FeatureDisabled` for a kind
/// this build has no declaration plane of.
#[cfg(all(feature = "alloc", feature = "codec-push", feature = "codec-declare"))]
pub fn multicast_tx_group_retraction<R>(
    what: crate::declare_form::GroupDeclaration,
    id: u64,
    key: crate::declare_form::GroupKey<'_>,
    f: impl FnOnce(&MulticastTxEncoded<'_>) -> R,
) -> Result<R, crate::send_wire_error::SendWireError> {
    use crate::declare_form::GroupDeclaration;
    use crate::send_wire_error::SendWireError;
    let refused = SendWireError::Codec(sce_forge_runtime::codec::CodecError::LengthOutOfRange);
    // A group holds no limits snapshot of its own: its key is bounded by the build's longest.
    let named = crate::lent_control::NamedKeyexpr::new(
        key.mapping_id,
        key.suffix.unwrap_or(""),
        crate::limits::MaxKeyexprBytesHeld::default(),
    )
    .map_err(|_| refused)?;
    match what {
        #[cfg(feature = "declare-subscriber")]
        GroupDeclaration::Subscriber => multicast_tx_declaration(
            &crate::lent_control::undeclare_subscriber_declaration(id, Some(&named)),
            f,
        )
        .ok_or(refused),
        #[cfg(feature = "declare-queryable")]
        GroupDeclaration::Queryable { .. } => multicast_tx_declaration(
            &crate::lent_control::undeclare_queryable_declaration(id, Some(&named)),
            f,
        )
        .ok_or(refused),
        #[cfg(feature = "liveliness-token")]
        GroupDeclaration::Token => multicast_tx_declaration(
            &crate::lent_control::undeclare_token_declaration(id, Some(&named)),
            f,
        )
        .ok_or(refused),
        #[cfg(not(all(
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "liveliness-token"
        )))]
        _ => {
            let _ = (id, named, f);
            Err(SendWireError::FeatureDisabled)
        }
    }
}

/// A Put or a Del a group session publishes, written from its parts
/// ([`crate::lent_push::write_publication`]) and handed to `f` as a message lent for the call:
/// framed as the owned Push of the same publication is, on `priority` and the channel
/// `reliable`. The writer's refusal, `LengthOutOfRange` (a key, a payload or a field past its
/// bound, which the owned builders refuse alike), with `f` not called.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub fn multicast_tx_publication<R>(
    key: crate::declare_form::GroupKey<'_>,
    kind: crate::sample::SampleKind,
    value: &[u8],
    meta: &crate::metadata::PushMetadata,
    reliable: bool,
    priority: Priority,
    f: impl FnOnce(&MulticastTxEncoded<'_>) -> R,
) -> Result<R, sce_forge_runtime::codec::CodecError> {
    #[cfg(feature = "pubsub-qos")]
    let qos = meta.qos.unwrap_or(crate::sample::QosLevel::DEFAULT);
    #[cfg(not(feature = "pubsub-qos"))]
    let qos = crate::sample::QosLevel::DEFAULT;
    let crate::declare_form::GroupKey { mapping_id, suffix } = key;
    let body = |sink: &mut crate::tx_buf::TxSink<'_>| {
        crate::lent_push::write_publication(sink, mapping_id, suffix, kind, value, meta)
    };
    let size = encoded_size(&body).ok_or(sce_forge_runtime::codec::CodecError::LengthOutOfRange)?;
    // The attachment is counted as far as the build writes it.
    #[cfg(all(feature = "transport-stats", feature = "pubsub-attachment"))]
    let attachment = meta.attachment.map_or(0, <[u8]>::len);
    #[cfg(all(feature = "transport-stats", not(feature = "pubsub-attachment")))]
    let attachment = 0;
    #[cfg(feature = "transport-stats")]
    let class = crate::network_message::publication_stats_class(
        mapping_id,
        suffix,
        kind,
        value.len(),
        attachment,
        |_| None,
    );
    #[cfg(not(feature = "transport-stats"))]
    let class = crate::stats::NetworkStatsClass::unread();
    Ok(f(&MulticastTxEncoded {
        framing: MulticastTxFraming::Publication {
            qos,
            reliable,
            priority,
        },
        size,
        body: &body,
        tally: MulticastTxTally::new(priority, class),
    }))
}

/// [`multicast_tx_push`] with or without a batch window ([`multicast_tx_push_batched`]).
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
fn multicast_tx_push_in<M, Q>(
    item: MulticastTxItem,
    tx_sn: &mut M,
    params: &crate::multicast_params::MulticastParams,
    conf: &TxQueueConf,
    queue: &mut Q,
    window: Option<&mut MulticastBatch>,
) -> PushOutcome
where
    M: MulticastTxMint + ?Sized,
    Q: MulticastTxQueue + ?Sized,
{
    // R2937 — the meta is resolved once, by the function a producer also asks
    // for the conduit it must hold (`multicast_tx_conduit`), so the conduit
    // locked and the conduit minted on cannot come from two readings.
    let meta = frame_meta(&item, params);
    // What THIS message can encode to, as the unicast send reserves it, and not the codec's
    // reserve hint for any message: the same reading a bounded group queue counts it by.
    let worst_case = multicast_tx_bytes(&item);
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
            FramedBody {
                meta,
                worst_case,
                body: crate::frame_encode::push_body(&push),
            },
            tx_sn,
            params,
            conf,
            queue,
            window,
        ),
        // A query to the group. Reliable (`frame_meta`); a large one (a long selector, a
        // value) re-frames as a fragment chain exactly like an oversize Push.
        #[cfg(all(feature = "codec-push", feature = "codec-request"))]
        MulticastTxItem::Request { request } => push_frame(
            FramedBody {
                meta,
                worst_case,
                body: |sink: &mut crate::tx_buf::TxSink<'_>| request.encode(sink),
            },
            tx_sn,
            params,
            conf,
            queue,
            window,
        ),
        // R311lq — queryable reply egress. Reliable like a reliable-ring put
        // (zenoh-pico replies via the same `_z_send_n_msg` multicast TX with
        // `Z_RELIABILITY_RELIABLE`); a large reply re-frames as a fragment
        // chain exactly like an oversize Push.
        #[cfg(feature = "codec-response")]
        MulticastTxItem::Response { response } => push_frame(
            // `meta.reliable` is pinned true for a reply (`frame_meta`).
            FramedBody {
                meta,
                worst_case,
                body: |sink: &mut crate::tx_buf::TxSink<'_>| response.encode(sink),
            },
            tx_sn,
            params,
            conf,
            queue,
            window,
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
                FramedBody {
                    meta,
                    worst_case,
                    body: |sink: &mut crate::tx_buf::TxSink<'_>| response_final.encode(sink),
                },
                tx_sn,
                params,
                conf,
                queue,
                window,
            )
        }
        // R311lr — declarer-side liveliness interest-response egress. Reliable —
        // zenoh-pico's `_z_send_declare` rides `_z_send_n_msg` with
        // `Z_RELIABILITY_RELIABLE` (src/net/primitives.c:52); a large held-token
        // keyexpr re-frames as a fragment chain exactly like an oversize Push.
        #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
        // `meta` pins a declare reply reliable and DEFAULT-band (no ext_qos),
        // the frame `encode_frame_with_declare` writes.
        MulticastTxItem::DeclareReply { declare } => push_frame(
            FramedBody {
                meta,
                worst_case,
                body: declare_body(&declare),
            },
            tx_sn,
            params,
            conf,
            queue,
            window,
        ),
        #[cfg(all(feature = "codec-declare", feature = "codec-push"))]
        MulticastTxItem::Declare { declare } => push_frame(
            FramedBody {
                meta,
                worst_case,
                body: declare_body(&declare),
            },
            tx_sn,
            params,
            conf,
            queue,
            window,
        ),
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Interest { interest } => push_frame(
            FramedBody {
                meta,
                worst_case,
                body: |sink: &mut crate::tx_buf::TxSink<'_>| interest.encode(sink),
            },
            tx_sn,
            params,
            conf,
            queue,
            window,
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
            // R2928 — the congestion control comes off the Push's own ext_qos,
            // as upstream's `congestion_control()` reads it
            // (`commons/zenoh-protocol/src/network/mod.rs` @ `NetworkBodyRef::Push(msg) => msg.ext_qos.get_congestion_control(),`).
            // The fragment re-frame re-emits the same frame `ext_qos` and mints its follow-ons
            // on the same conduit; `None` / DEFAULT is byte-identical to the pre-qos wire.
            publication_frame_meta(
                crate::declare_ext_qos::read_push_qos(push),
                *reliable,
                *priority,
                params,
            )
        }
        // A query's band comes off its own `ext_qos`, clamped as a Response's is; it rides the
        // reliable ring, as the unicast query does.
        #[cfg(all(feature = "codec-push", feature = "codec-request"))]
        MulticastTxItem::Request { request } => qos_frame_meta(
            crate::declare_ext_qos::read_request_qos(request),
            true,
            params,
        ),
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
                express: qos.is_express(),
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
                express: qos.is_express(),
            }
        }
        // The declare reply is DEFAULT-band: no frame ext_qos, no per-priority
        // conduit.
        #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
        MulticastTxItem::DeclareReply { declare } => declare_frame_meta(declare),
        #[cfg(all(feature = "codec-declare", feature = "codec-push"))]
        MulticastTxItem::Declare { declare } => declare_frame_meta(declare),
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Interest { interest } => {
            control_frame_meta(crate::declare_ext_qos::read_interest_qos(interest))
        }
    }
}

/// How a `Declare` the group carries is framed: DEFAULT-band, no frame `ext_qos`, reliable, and
/// droppable as its own `ext_qos` says.
#[cfg(all(
    feature = "alloc",
    feature = "codec-declare",
    any(
        feature = "codec-push",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
fn declare_frame_meta(declare: &crate::transport_profile::owned::DeclareOwned) -> FrameMeta {
    control_frame_meta(crate::declare_ext_qos::read_declare_qos(declare))
}

/// How a `Declare` the group carries is written: one writer for the declare reply and the
/// declaration alike, so the frame walk is compiled once for both.
#[cfg(all(
    feature = "alloc",
    feature = "codec-declare",
    any(
        feature = "codec-push",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
fn declare_body(
    declare: &crate::transport_profile::owned::DeclareOwned,
) -> impl Fn(&mut crate::tx_buf::TxSink<'_>) -> Result<(), sce_forge_runtime::codec::CodecError> + '_
{
    move |sink| declare.encode(sink)
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
pub fn multicast_tx_conduit(
    item: &MulticastTxItem,
    params: &crate::multicast_params::MulticastParams,
) -> Priority {
    frame_meta(item, params).priority
}

/// Whether a push of `item` onto a group of `params` may be dropped: zenoh's `is_droppable`, read
/// off the item as the push reads it. A producer that holds its conduit across a wait for room
/// asks this before it takes the conduit, so that a droppable push is not held behind a blocking
/// one for the whole of that one's `wait_before_close`.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
pub fn multicast_tx_droppable(
    item: &MulticastTxItem,
    params: &crate::multicast_params::MulticastParams,
) -> bool {
    frame_meta(item, params).droppable
}

/// The most bytes `item`'s network message encodes to: what its frame is reserved by when it is
/// pushed, and what it counts for on a lane that bounds a group's queue ([`MulticastTxLanes`]).
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
pub fn multicast_tx_bytes(item: &MulticastTxItem) -> usize {
    match item {
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Push { push, .. } => crate::frame_encode::push_capacity_hint(push),
        #[cfg(all(feature = "codec-push", feature = "codec-request"))]
        MulticastTxItem::Request { request } => {
            wz_codecs::request::RequestWire::measure(&**request).len()
        }
        #[cfg(feature = "codec-response")]
        MulticastTxItem::Response { response } => {
            wz_codecs::response::ResponseWire::measure(&**response).len()
        }
        #[cfg(feature = "codec-response-final")]
        MulticastTxItem::ResponseFinal { request_id, qos } => {
            let response_final =
                crate::response_final_build::build_response_final(*request_id, *qos);
            wz_codecs::response_final::ResponseFinalWire::measure(&response_final).len()
        }
        #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
        MulticastTxItem::DeclareReply { declare } => {
            wz_codecs::declare::DeclareWire::measure(&**declare).len()
        }
        #[cfg(all(feature = "codec-declare", feature = "codec-push"))]
        MulticastTxItem::Declare { declare } => {
            wz_codecs::declare::DeclareWire::measure(&**declare).len()
        }
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Interest { interest } => {
            wz_codecs::interest::InterestWire::measure(&**interest).len()
        }
    }
}

/// The bound of a multicast group's outbound queue, lane by lane, and zenoh's congestion mark on
/// each lane: the lanes the tokio engine's group pipeline is shaped into, kept for a queue whose
/// producers and writer take turns on one thread (the cooperative engine's group).
///
/// A lane holds `TxQueueConf::sizes` batches of the group's batch size, one lane for every
/// priority when the group runs no QoS ([`TxQueueShape::lane_bytes`](crate::link::TxQueueShape::lane_bytes)),
/// and a message is let on while the lane holds less than that, counted by the bytes it encodes to
/// (`multicast_tx_bytes` on the heap profile). What a sender is answered before it waits is the
/// one rule every bounded lane follows ([`lane_room_at_once`](crate::link::lane_room_at_once)); a
/// wait that runs out raises the mark, and a message written lowers it, as zenoh's pipeline lowers
/// it when a written batch returns to its pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastTxLanes {
    shape: crate::link::TxQueueShape,
    /// Bytes each lane holds, by lane.
    held: [usize; Priority::NUM],
    /// The congestion mark of each lane.
    congested: [bool; Priority::NUM],
    /// Messages dropped for want of room, by their own priority.
    dropped: [u32; Priority::NUM],
}

impl MulticastTxLanes {
    /// Empty lanes of `shape`, no mark raised.
    pub const fn new(shape: crate::link::TxQueueShape) -> Self {
        Self {
            shape,
            held: [0; Priority::NUM],
            congested: [false; Priority::NUM],
            dropped: [0; Priority::NUM],
        }
    }

    /// The lanes a group of `params` sends through: its queue's sizes in batches of its batch
    /// size, one lane when it runs no QoS, as the tokio engine shapes its group's pipeline.
    pub fn of_group(params: &crate::multicast_params::MulticastParams) -> Self {
        let batch = usize::from(params.batch_size);
        Self::new(params.tx_queue.shape(params.is_qos, batch, batch))
    }

    /// The bytes the lane of `priority` holds at most, when `priority` has a lane of its own:
    /// every priority on a group that runs QoS, DEFAULT alone otherwise. `None` is a priority
    /// whose messages take DEFAULT's lane.
    pub fn own_lane_bytes(&self, priority: Priority) -> Option<usize> {
        (self.shape.qos || priority == Priority::DEFAULT).then(|| self.shape.lane_bytes(priority))
    }

    /// The index, by priority wire byte, of the lane a message of `priority` takes: its own on a
    /// QoS group, the DEFAULT one otherwise.
    pub fn lane_index(&self, priority: Priority) -> usize {
        usize::from(self.lane(priority).wire_byte())
    }

    /// The lane a message of `priority` takes: its own on a QoS group, the DEFAULT one otherwise.
    fn lane(&self, priority: Priority) -> Priority {
        if self.shape.qos {
            priority
        } else {
            Priority::DEFAULT
        }
    }

    /// Whether `priority`'s lane holds less than its bound.
    pub fn has_room(&self, priority: Priority) -> bool {
        *self.lane(priority).of(&self.held) < self.shape.lane_bytes(priority)
    }

    /// What a message of `priority` asking with `wait` is answered before it waits:
    /// [`lane_room_at_once`](crate::link::lane_room_at_once) over its lane. `None` is a message
    /// that has to wait for the writer.
    pub fn room_at_once(
        &mut self,
        priority: Priority,
        wait: crate::link::RoomWait,
    ) -> Option<crate::link::LinkRoom> {
        let has_room = self.has_room(priority);
        let lane = self.lane(priority);
        crate::link::lane_room_at_once(lane.of_mut(&mut self.congested), has_room, wait)
    }

    /// A message of `priority` took `bytes` of its lane.
    pub fn taken(&mut self, priority: Priority, bytes: usize) {
        let held = self.lane(priority).of_mut(&mut self.held);
        *held = held.saturating_add(bytes);
    }

    /// A message of `priority` that took `bytes` of its lane left it for the wire: room is made,
    /// and the lane's mark is lowered.
    pub fn written(&mut self, priority: Priority, bytes: usize) {
        let lane = self.lane(priority);
        let held = lane.of_mut(&mut self.held);
        *held = held.saturating_sub(bytes);
        *lane.of_mut(&mut self.congested) = false;
    }

    /// A message of `priority` found no room within its wait and was dropped: its lane's mark is
    /// raised, and the drop is counted by the message's own priority.
    pub fn dropped(&mut self, priority: Priority) {
        *self.lane(priority).of_mut(&mut self.congested) = true;
        let dropped = priority.of_mut(&mut self.dropped);
        *dropped = dropped.saturating_add(1);
    }

    /// How many messages of `priority` were dropped for want of room.
    pub fn drops(&self, priority: Priority) -> u32 {
        *priority.of(&self.dropped)
    }
}

/// R2937 — where a push mints its sequence numbers: the whole set of a group's
/// conduits ([`MulticastTxConduits`](crate::sn::MulticastTxConduits)), or the
/// one conduit a producer holds ([`MulticastTxConduit`]).
pub trait MulticastTxMint {
    /// Mint the next SN on the `(priority, reliable)` conduit.
    fn mint(&mut self, priority: Priority, reliable: bool) -> crate::sn::Sn;
    /// The SN ring's mask.
    fn mask(&self) -> crate::sn::Sn;
}

impl MulticastTxMint for crate::sn::MulticastTxConduits {
    fn mint(&mut self, priority: Priority, reliable: bool) -> crate::sn::Sn {
        crate::sn::MulticastTxConduits::mint(self, priority, reliable)
    }

    fn mask(&self) -> crate::sn::Sn {
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
    fn mint(&mut self, priority: Priority, reliable: bool) -> crate::sn::Sn {
        assert_eq!(
            priority, self.priority,
            "a push minted on a conduit its producer does not hold"
        );
        self.sn.mint(reliable)
    }

    fn mask(&self) -> crate::sn::Sn {
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
    /// Whether the message leaves at once even inside a batch window, as its own `ext_qos`
    /// says: the window's open frame goes with it.
    express: bool,
}

/// A message as [`push_frame`] frames it: how it is framed, the most bytes it can encode to,
/// and the encoder of its body.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
struct FramedBody<P> {
    meta: FrameMeta,
    worst_case: usize,
    body: P,
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
fn push_frame<M, Q, P>(
    message: FramedBody<P>,
    tx_sn: &mut M,
    params: &crate::multicast_params::MulticastParams,
    conf: &TxQueueConf,
    queue: &mut Q,
    window: Option<&mut MulticastBatch>,
) -> PushOutcome
where
    M: MulticastTxMint + ?Sized,
    Q: MulticastTxQueue + ?Sized,
    P: Fn(&mut crate::tx_buf::TxSink<'_>) -> Result<(), sce_forge_runtime::codec::CodecError>,
{
    let FramedBody {
        meta,
        worst_case,
        body,
    } = message;
    let FrameMeta {
        priority,
        ext_qos,
        reliable,
        droppable,
        express,
    } = meta;
    // The group's batch less the `BatchHeader` of a compressing group, so that a datagram, header
    // included, is within the batch size every member of the group reads it against.
    let mtu = params.frame_budget();
    let mut window = window;
    // Inside a window the message joins its conduit's open frame when it can, with no room
    // asked and no SN spent: that frame already has both. An express message takes the frame
    // with it.
    if let Some(open) = window.as_deref_mut() {
        if open.append(reliable, mtu, &body) {
            if express {
                open.flush(priority, params, queue);
            }
            return PushOutcome::Pushed;
        }
        // Another reliability, or no room behind the open frame: the frame leaves and the
        // message opens the next, as zenoh-pico's overflow does
        // (`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_batch_overflow(`).
        open.flush(priority, params, queue);
    }
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
    // The SN as the frame head writes it and as a datagram on the queue names it.
    let wire_sn = crate::sn::to_wire(sn);
    let flags = crate::frame_encode::frame_flags(reliable);
    // A compressing group does not lend: a lent frame is written once, into the slot the link
    // sends, and the batch around it is built from the frame's bytes. Nor does a window: a
    // lent slot is the queue's once it is filled, and a window's frame stays open.
    #[cfg(feature = "transport-tx-lend")]
    if !params.compression && window.is_none() {
        // A frame sent whole is at most one batch (past it, it is fragmented),
        // so that is the most a lent slot must hold. NOT the codec's
        // `MAX_ENCODED_BYTES`, which sizes a vector's first reservation and is
        // exceeded by any payload larger than it.
        let want = mtu;
        // Whether the queue lent a slot: one that did and was refused the frame is a frame past
        // the batch, which is cut into a chain of fragments written into slots of their own.
        let mut lent = false;
        let mut fill = |slot: &mut crate::tx_buf::SliceTxBuf<'_>| {
            lent = true;
            // A slot longer than the batch refuses the frame where it crosses the batch, before
            // the payload that would carry it past is copied in.
            slot.hold_to(mtu);
            crate::frame_encode::encode_frame_envelope_into(slot, wire_sn, flags, ext_qos, &body)
                .is_ok()
        };
        if queue.enqueue_lent(priority, reliable, wire_sn, want, &mut fill) {
            return PushOutcome::Pushed;
        }
        // A build that cuts no chain sends a frame past the batch as the heap path does.
        #[cfg(not(feature = "transport-fragmentation"))]
        let _ = lent;
        #[cfg(feature = "transport-fragmentation")]
        if lent {
            use crate::frame_encode::{
                write_fragment, BodyEncoder, FragmentBody, FragmentPlan, FragmentSpan,
            };
            use crate::tx_buf::try_encoded_len;
            let encode: &BodyEncoder<'_> = &body;
            // A message whose encoder refuses it takes the heap path below, which answers it.
            if let Ok(body_len) = try_encoded_len(encode) {
                let mut plan = FragmentPlan::new(body_len, mtu, sn, tx_sn.mask(), ext_qos);
                let mut emitted = 0usize;
                while let Some(span) = plan.next_span() {
                    // Each fragment past the first asks for room and takes the conduit's next
                    // SN, as the heap chain below does; one with no room stops the chain with
                    // the drop marker, on the SN it would have taken.
                    let span = if emitted > 0 && !has_room(queue, &mut deadline) {
                        FragmentSpan::stop(span.sn)
                    } else {
                        span
                    };
                    if emitted > 0 {
                        tx_sn.mint(priority, reliable);
                    }
                    let mut write = |slot: &mut crate::tx_buf::SliceTxBuf<'_>| {
                        write_fragment(
                            slot,
                            &span,
                            FragmentBody::Encoded(encode),
                            reliable,
                            ext_qos,
                        )
                        .is_ok()
                    };
                    let span_sn = crate::sn::to_wire(span.sn);
                    if !queue.enqueue_lent(priority, reliable, span_sn, mtu, &mut write) {
                        // A queue whose lend this fragment did not fit builds it on the heap.
                        let mut bytes = Vec::new();
                        if write_fragment(
                            &mut bytes,
                            &span,
                            FragmentBody::Encoded(encode),
                            reliable,
                            ext_qos,
                        )
                        .is_ok()
                        {
                            enqueue_wire(
                                queue,
                                params,
                                MulticastTxDatagram {
                                    priority,
                                    reliable,
                                    sn: span_sn,
                                    bytes,
                                },
                            );
                        }
                    }
                    if span.drop_marker {
                        return PushOutcome::Congested;
                    }
                    emitted = emitted.saturating_add(1);
                    deadline.next_fragment();
                }
                return PushOutcome::Pushed;
            }
        }
    }
    // Opened inside a window, the frame is written into the window's own storage and stays open
    // for the messages after it; one past the batch leaves as a chain below.
    if !express {
        if let Some(open) = window.as_deref_mut() {
            let opened = open.open_with(reliable, sn, mtu, |buf| {
                crate::frame_encode::encode_frame_envelope_into(buf, wire_sn, flags, ext_qos, &body)
                    .is_ok()
            });
            if opened {
                return PushOutcome::Pushed;
            }
        }
    }
    // The vector refuses no write, but the body can refuse its message: nothing is queued then,
    // and the SN minted for it is skipped, as a chain its drop marker stops skips the rest.
    let frame = match crate::frame_encode::encode_frame_envelope(
        wire_sn, flags, worst_case, ext_qos, &body,
    ) {
        Ok(frame) => frame,
        Err(refused) => return PushOutcome::Refused(refused),
    };
    #[cfg(feature = "transport-fragmentation")]
    if frame.len() > mtu {
        let body = crate::frame_encode::frame_wire_body(&frame, wire_sn, ext_qos);
        let mut chain =
            crate::frame_encode::FragmentChain::new(body, reliable, mtu, sn, tx_sn.mask(), ext_qos);
        let mut emitted = 0usize;
        while chain.remaining_fragments() > 0 {
            // The SN the fragment this iteration sends carries — and the one
            // the stop marker takes if there is no room for it.
            let this_sn = crate::sn::to_wire(chain.next_sn());
            if emitted > 0 {
                if !has_room(queue, &mut deadline) {
                    let marker =
                        crate::frame_encode::build_fragment_drop_wire(this_sn, reliable, ext_qos);
                    tx_sn.mint(priority, reliable);
                    enqueue_wire(
                        queue,
                        params,
                        MulticastTxDatagram {
                            priority,
                            reliable,
                            sn: this_sn,
                            bytes: marker,
                        },
                    );
                    return PushOutcome::Congested;
                }
                tx_sn.mint(priority, reliable);
            }
            let Some(fragment) = chain.next() else {
                // `remaining_fragments() > 0` and `next() == None` are the same
                // predicate negated, so this arm is unreachable.
                break;
            };
            enqueue_wire(
                queue,
                params,
                MulticastTxDatagram {
                    priority,
                    reliable,
                    sn: this_sn,
                    bytes: fragment,
                },
            );
            emitted = emitted.saturating_add(1);
            deadline.next_fragment();
        }
        return PushOutcome::Pushed;
    }
    #[cfg(not(feature = "transport-fragmentation"))]
    let _ = ext_qos;
    match window {
        // Opened inside a window, the frame stays open for the messages after it.
        Some(open) if !express => open.hold(reliable, sn, frame),
        _ => enqueue_wire(
            queue,
            params,
            MulticastTxDatagram {
                priority,
                reliable,
                sn: wire_sn,
                bytes: frame,
            },
        ),
    }
    PushOutcome::Pushed
}

/// One conduit's open frame inside a group's batch window ([`multicast_tx_push_batched`]): the
/// `T_MID_FRAME` the window's messages are appended to, behind the one sequence number the
/// frame took when it was opened. Empty outside a window, and between two frames.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
#[derive(Debug, Default)]
pub struct MulticastBatch {
    /// Storage the batch keeps from one frame to the next; the open frame is its first `len`
    /// bytes. A build whose encoders write through `dyn TxBuf` (`transport-tx-lend`) keeps it a
    /// batch long and writes a frame into it as into a fixed buffer held to the batch, so a
    /// message that would carry the frame past the batch is refused before its payload is copied
    /// in. The bytes past `len` are no frame's.
    buf: alloc::vec::Vec<u8>,
    /// The open frame's length in `buf`.
    len: usize,
    open: Option<OpenFrame>,
}

/// The frame a [`MulticastBatch`] holds open.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
#[derive(Debug, Clone, Copy)]
struct OpenFrame {
    reliable: bool,
    sn: crate::sn::Sn,
}

#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
impl MulticastBatch {
    /// No frame open.
    pub const fn new() -> Self {
        Self {
            buf: alloc::vec::Vec::new(),
            len: 0,
            open: None,
        }
    }

    /// No frame open, with storage for a frame of `budget` bytes taken now: the window's frames
    /// are written into it, and none of them allocates.
    pub fn with_budget(budget: usize) -> Self {
        Self {
            buf: alloc::vec::Vec::with_capacity(budget),
            len: 0,
            open: None,
        }
    }

    /// Whether no frame is open.
    pub fn is_empty(&self) -> bool {
        self.open.is_none()
    }

    /// Put the open frame, if one is, on `queue` as `priority`'s datagram, the way every datagram
    /// of the group goes onto it (compressed when the group compresses), and hold none after.
    /// No room is asked: the frame was given its room when it was opened. A queue that lends a
    /// slot takes a copy of the frame and the batch keeps its storage; otherwise the frame is
    /// handed over: as a copy of exactly the frame when the storage is the batch the window
    /// writes into, which the batch keeps, and as the storage itself when that is the frame.
    pub fn flush<Q: MulticastTxQueue + ?Sized>(
        &mut self,
        priority: Priority,
        params: &crate::multicast_params::MulticastParams,
        queue: &mut Q,
    ) {
        let Some(open) = self.open.take() else {
            return;
        };
        // A compressing group's frame is compressed on its way to the queue, which only the
        // datagram handed over is.
        if !params.compression {
            let bytes = self.frame();
            let mut fill = |slot: &mut crate::tx_buf::SliceTxBuf<'_>| {
                crate::tx_buf::TxBuf::append(slot, bytes).is_ok()
            };
            let sn = crate::sn::to_wire(open.sn);
            if queue.enqueue_lent(priority, open.reliable, sn, bytes.len(), &mut fill) {
                self.len = 0;
                return;
            }
        }
        let bytes = self.take_frame();
        enqueue_wire(
            queue,
            params,
            MulticastTxDatagram {
                priority,
                reliable: open.reliable,
                sn: crate::sn::to_wire(open.sn),
                bytes,
            },
        );
    }

    /// The open frame's bytes.
    fn frame(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }

    /// The open frame's bytes, taken out of the batch. Storage longer than the frame is the
    /// batch a window writes into: it stays the batch's and a copy of exactly the frame is
    /// taken, so a queued datagram holds no batch of its own. Storage that is the frame (a
    /// vector's, or a frame held whole) is taken as it is.
    fn take_frame(&mut self) -> alloc::vec::Vec<u8> {
        let len = core::mem::take(&mut self.len);
        if len < self.buf.len() {
            return self.buf.get(..len).unwrap_or_default().to_vec();
        }
        core::mem::take(&mut self.buf)
    }

    /// Append the message `body` encodes to the open frame, when one is open on the `reliable`
    /// channel and the frame stays within `mtu` with it. Whether it was appended; a frame it was
    /// not appended to is as it was.
    fn append<P>(&mut self, reliable: bool, mtu: usize, body: &P) -> bool
    where
        P: Fn(&mut crate::tx_buf::TxSink<'_>) -> Result<(), sce_forge_runtime::codec::CodecError>,
    {
        let Some(open) = self.open else {
            return false;
        };
        if open.reliable != reliable {
            return false;
        }
        self.write_held(mtu, |buf| {
            body(&mut crate::tx_buf::TxSink::new(buf)).is_ok()
        })
    }

    /// Open a frame on the `reliable` channel that took `sn`, `write` writing it into the
    /// batch's storage held to `mtu`: whether it was opened. A frame `write` cannot write
    /// within `mtu` leaves the batch as it was, with no frame open.
    fn open_with(
        &mut self,
        reliable: bool,
        sn: crate::sn::Sn,
        mtu: usize,
        write: impl FnOnce(&mut crate::tx_buf::EncodeBuf<'_>) -> bool,
    ) -> bool {
        debug_assert!(self.open.is_none(), "one frame is open at a time");
        self.len = 0;
        let opened = self.write_held(mtu, write);
        if opened {
            self.open = Some(OpenFrame { reliable, sn });
        }
        opened
    }

    /// Write what `write` writes after the open frame, the frame held to `mtu`: whether it was
    /// written whole within `mtu`, the frame grown by it. A write that was not leaves the frame
    /// as it was.
    ///
    /// The storage is made a batch long once and stays so, and is written as a fixed buffer
    /// held to the batch: a write past it is refused as it is made.
    #[cfg(feature = "transport-tx-lend")]
    fn write_held(
        &mut self,
        mtu: usize,
        write: impl FnOnce(&mut crate::tx_buf::EncodeBuf<'_>) -> bool,
    ) -> bool {
        use crate::tx_buf::TxBuf;
        if self.buf.len() < mtu {
            self.buf.resize(mtu, 0);
        }
        // A frame already past `mtu` (one held whole) has no room after it.
        let Some(room) = self.buf.get_mut(self.len..mtu) else {
            return false;
        };
        let mut room = crate::tx_buf::SliceTxBuf::new(room);
        if !write(&mut room) {
            return false;
        }
        let written = room.len();
        self.len = self.len.saturating_add(written);
        true
    }

    /// See the lending form above. A vector refuses no write, so the frame is measured against
    /// `mtu` once it is written.
    #[cfg(not(feature = "transport-tx-lend"))]
    fn write_held(
        &mut self,
        mtu: usize,
        write: impl FnOnce(&mut crate::tx_buf::EncodeBuf<'_>) -> bool,
    ) -> bool {
        self.buf.truncate(self.len);
        if write(&mut self.buf) && self.buf.len() <= mtu {
            self.len = self.buf.len();
            return true;
        }
        self.buf.truncate(self.len);
        false
    }

    /// Hold `bytes`, a whole frame on the `reliable` channel that took `sn`, open: one past the
    /// batch, which a build that cuts no chain holds as it is.
    fn hold(&mut self, reliable: bool, sn: crate::sn::Sn, bytes: alloc::vec::Vec<u8>) {
        debug_assert!(self.open.is_none(), "one frame is open at a time");
        self.len = bytes.len();
        self.buf = bytes;
        self.open = Some(OpenFrame { reliable, sn });
    }
}

/// Put one datagram on the queue as the group's wire carries it: when the group compresses
/// (`transport/multicast/compression/enabled`), the frame becomes a batch, the one-byte
/// `BatchHeader` in front of its payload, which is lz4-compressed when that is smaller
/// ([`crate::compression::compress_batch`]), as upstream's batch writes it for a link whose
/// config says `is_compression`. Every datagram the group's links send takes this one way
/// in: a frame, each fragment of a chain, and the marker that stops a chain.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
fn enqueue_wire<Q: MulticastTxQueue + ?Sized>(
    queue: &mut Q,
    params: &crate::multicast_params::MulticastParams,
    #[cfg_attr(not(feature = "transport-compression"), allow(unused_mut))]
    mut datagram: MulticastTxDatagram,
) {
    #[cfg(feature = "transport-compression")]
    if params.compression {
        datagram.bytes = crate::compression::compress_batch(&datagram.bytes);
    }
    #[cfg(not(feature = "transport-compression"))]
    let _ = params;
    queue.enqueue(datagram);
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
        #[cfg(all(feature = "codec-push", feature = "codec-request"))]
        MulticastTxItem::Request { request } => (
            crate::declare_ext_qos::read_request_qos(request).priority(),
            crate::network_message::request_stats_class(request, |_| None),
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
        #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
        MulticastTxItem::DeclareReply { declare } => (
            crate::declare_ext_qos::read_declare_qos(declare).priority(),
            NetworkStatsClass::control(MessageLabel::Declare),
        ),
        // Counted as the interest's reply above is: at its own band, as a control message.
        #[cfg(all(feature = "codec-declare", feature = "codec-push"))]
        MulticastTxItem::Declare { declare } => (
            crate::declare_ext_qos::read_declare_qos(declare).priority(),
            NetworkStatsClass::control(MessageLabel::Declare),
        ),
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Interest { interest } => (
            crate::declare_ext_qos::read_interest_qos(interest).priority(),
            NetworkStatsClass::control(MessageLabel::Interest),
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
    )
))]
#[derive(Clone, Copy)]
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
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

    /// The tally of a message a group's producer writes from its parts, with no owned message to
    /// read: of `class` on its own band `priority`. A build without `transport-stats` keeps
    /// neither, and its senders hand `NetworkStatsClass::unread`.
    pub fn new(priority: Priority, class: crate::stats::NetworkStatsClass) -> Self {
        #[cfg(feature = "transport-stats")]
        {
            Self { priority, class }
        }
        #[cfg(not(feature = "transport-stats"))]
        {
            let _ = (priority, class);
            Self {}
        }
    }

    /// The tally of the reply `parts` describes, written from them with no owned `Response`, as
    /// [`Self::of`] reads the owned one the same parts build: on the reply's own band, by its
    /// class.
    #[cfg(feature = "codec-response")]
    pub fn of_reply_parts(parts: &crate::reply_stage::ReplyParts<'_>) -> Self {
        #[cfg(feature = "transport-stats")]
        {
            Self::new(
                parts.qos.priority(),
                crate::network_message::reply_parts_stats_class(parts),
            )
        }
        #[cfg(not(feature = "transport-stats"))]
        {
            let _ = parts;
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

/// A reliable, DEFAULT-band literal Put as the build's [`MulticastTxOffer`]: the owned
/// item `multicast_put_literal` builds on the heap profile, or the borrowed
/// `MulticastTxPut` over `keyexpr` and `payload` on a build with no allocator. One
/// call for both, so a caller that queues a Put names no profile. `None` when the
/// owned message cannot be built (a keyexpr longer than the codec's text bound); the
/// borrowed form reports that where it is framed (`MulticastTxRefused::Unencodable`).
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub fn multicast_tx_offer_put_literal<'a>(
    keyexpr: &'a str,
    payload: &'a [u8],
) -> Option<MulticastTxOffer<'a>> {
    multicast_put_literal(keyexpr, payload).ok()
}
/// See the heap form of this function.
#[cfg(all(
    not(feature = "alloc"),
    feature = "codec-push",
    feature = "transport-tx-lend"
))]
pub fn multicast_tx_offer_put_literal<'a>(
    keyexpr: &'a str,
    payload: &'a [u8],
) -> Option<MulticastTxOffer<'a>> {
    Some(MulticastTxPut::literal(keyexpr, payload))
}

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
    /// The message does not encode (a keyexpr past the protocol's `u16` length, or a
    /// payload past its `u32` length).
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
    use crate::tx_buf::{SliceTxBuf, TxBuf};

    // Composed before the SN is minted, so a Put past its protocol bounds leaves the
    // conduit's ring as it was.
    let push = crate::lent_push::literal_put(put.keyexpr, put.payload)
        .map_err(|_| MulticastTxRefused::Unencodable)?;
    let priority = effective_mcast_priority(put.priority, params.is_qos);
    let ext_qos = frame_ext_qos(priority);
    let reliable = put.reliable;
    let sn = tx_sn.mint(priority, reliable);
    let mtu = core::cmp::min(params.batch_size as usize, datagram.len());
    let flags = crate::frame_encode::frame_flags(reliable);
    let body = |sink: &mut crate::tx_buf::TxSink<'_>| push.encode(sink);

    // The frame whole, when it fits the batch: the hold makes a refusal mean "past it".
    let whole = {
        let mut buf = SliceTxBuf::new(&mut *datagram);
        buf.hold_to(mtu);
        crate::frame_encode::encode_frame_envelope_into(
            &mut buf,
            crate::sn::to_wire(sn),
            flags,
            ext_qos,
            body,
        )
        .ok()
        .map(|()| TxBuf::len(&buf))
    };
    // The length is what the buffer over `datagram` holds.
    if let Some(frame) = whole.and_then(|len| datagram.get(..len)) {
        send(frame);
        return Ok(1);
    }

    #[cfg(feature = "transport-fragmentation")]
    {
        use crate::frame_encode::{write_fragment, FragmentBody, FragmentPlan};
        let encode: &crate::frame_encode::BodyEncoder<'_> = &body;
        let body_len =
            crate::tx_buf::try_encoded_len(encode).map_err(|_| MulticastTxRefused::Unencodable)?;
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
            send(
                datagram
                    .get(..len)
                    .ok_or(MulticastTxRefused::DatagramTooSmall)?,
            );
            sent = sent.saturating_add(1);
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
            any(feature = "liveliness-token", feature = "declare-subscriber")
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
                any(feature = "liveliness-token", feature = "declare-subscriber")
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
            whatami: WhatAmI::Peer,
            zid: crate::session_zid::SessionZid::from_array([1, 2, 3, 4]),
            lease_ms: 5_000,
            join_interval_ms: 50,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos,
            compression: false,
            tx_queue: TxQueueConf::of_snapshot(
                &crate::policy::SessionPolicy::defaults(),
                &crate::limits::SessionLimits::BUILD,
            ),
            link_rx: crate::session_init_params::LinkRxConf::default(),
            join_rule: crate::multicast_params::GroupJoinRule::Pico,
            max_sessions: None,
            policy: crate::policy::SessionPolicy::defaults(),
            limits: crate::limits::SessionLimits::BUILD,
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
            whatami: WhatAmI::Peer,
            zid: crate::session_zid::SessionZid::from_array([1, 2, 3, 4]),
            lease_ms: 5_000,
            join_interval_ms: 50,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size,
            is_qos: false,
            compression: false,
            tx_queue: TxQueueConf::of_snapshot(
                &crate::policy::SessionPolicy::defaults(),
                &crate::limits::SessionLimits::BUILD,
            ),
            link_rx: crate::session_init_params::LinkRxConf::default(),
            join_rule: crate::multicast_params::GroupJoinRule::Pico,
            max_sessions: None,
            policy: crate::policy::SessionPolicy::defaults(),
            limits: crate::limits::SessionLimits::BUILD,
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

    /// A lane lets messages on while it holds less than its bound, `sizes` batches of the group's
    /// batch, and none past it; what is written makes room and lowers the mark a drop raised. A
    /// group that runs no QoS bounds every priority by its one DEFAULT lane, and a drop is
    /// counted by the message's own priority.
    #[test]
    fn a_group_lane_holds_its_batches_and_a_drop_marks_it() {
        let mut params = params(100);
        params.tx_queue.sizes = [2; Priority::NUM];
        let mut lanes = MulticastTxLanes::of_group(&params);
        let drop = RoomWait::Drop { wait_us: 1_000 };
        assert_eq!(
            lanes.room_at_once(Priority::DEFAULT, drop),
            Some(LinkRoom::Free)
        );
        lanes.taken(Priority::DEFAULT, 150);
        assert_eq!(
            lanes.room_at_once(Priority::DEFAULT, drop),
            Some(LinkRoom::Free),
            "150 of 200 bytes"
        );
        lanes.taken(Priority::DEFAULT, 60);
        assert!(!lanes.has_room(Priority::DEFAULT));
        assert!(
            !lanes.has_room(Priority::RealTime),
            "a group without QoS has one lane"
        );
        assert_eq!(
            lanes.room_at_once(Priority::DEFAULT, drop),
            None,
            "a wait for the writer"
        );
        lanes.dropped(Priority::RealTime);
        assert_eq!(lanes.drops(Priority::RealTime), 1);
        assert_eq!(lanes.drops(Priority::DEFAULT), 0);
        assert_eq!(
            lanes.room_at_once(Priority::DEFAULT, drop),
            Some(LinkRoom::Congested),
            "the mark answers a droppable ask at once"
        );
        lanes.written(Priority::DEFAULT, 150);
        assert_eq!(
            lanes.room_at_once(Priority::DEFAULT, drop),
            Some(LinkRoom::Free),
            "a write makes room and lowers the mark"
        );
    }

    /// A message lent for the call is framed as the owned one is: the same datagrams, on the
    /// same conduit, under the same sequence numbers.
    #[test]
    fn a_lent_message_is_framed_as_the_owned_one_is() {
        let params = params(512);
        let owned = put(true, b"lent");
        let push = crate::push_build::build_push_literal("k", b"lent").unwrap();
        let body = crate::frame_encode::push_body(&push);
        let lent = MulticastTxEncoded {
            framing: MulticastTxFraming::OwnBand {
                qos: crate::declare_ext_qos::read_push_qos(&push),
                reliable: true,
            },
            size: multicast_tx_bytes(&owned),
            body: &body,
            tally: MulticastTxTally::of(&owned),
        };
        assert_eq!(
            multicast_tx_encoded_conduit(&lent, &params),
            multicast_tx_conduit(&owned, &params)
        );
        let mask = mask_from_res(params.seq_num_res);
        let (mut by_owned, mut by_lent) = (Scripted::default(), Scripted::default());
        let mut sn_owned = MulticastTxConduits::new(mask);
        let mut sn_lent = MulticastTxConduits::new(mask);
        assert_eq!(
            multicast_tx_push(
                owned,
                &mut sn_owned,
                &params,
                &params.tx_queue,
                &mut by_owned
            ),
            PushOutcome::Pushed
        );
        assert_eq!(
            multicast_tx_push_encoded(
                &lent,
                &mut sn_lent,
                &params,
                &params.tx_queue,
                &mut by_lent,
                None
            ),
            PushOutcome::Pushed
        );
        assert_eq!(by_lent.enqueued, by_owned.enqueued);
        assert_eq!(by_lent.sns, by_owned.sns);
        assert_eq!(by_lent.asks.len(), by_owned.asks.len());
    }

    /// A message counts on a lane for what its frame is reserved by when it is pushed, so a
    /// larger payload counts for at least its length more.
    #[test]
    fn a_message_counts_for_the_bytes_it_encodes_to() {
        let small = multicast_tx_bytes(&put(true, b"v"));
        let large = multicast_tx_bytes(&put(true, &[7u8; 300]));
        assert!(small > 1, "{small}");
        assert!(large >= small + 299, "{small} then {large}");
    }

    /// [`put`], marked express in its own `ext_qos`.
    fn express_put(payload: &[u8]) -> MulticastTxItem {
        let mut push = crate::push_build::build_push_literal("k", payload).unwrap();
        crate::declare_ext_qos::set_push_qos(
            &mut push,
            crate::sample::QosLevel::DEFAULT.with_express(true),
        )
        .unwrap();
        MulticastTxItem::Push {
            push: Box::new(push),
            reliable: true,
            priority: Priority::DEFAULT,
        }
    }

    /// The sequence number and the network messages of one `T_MID_FRAME` datagram.
    fn frame_of(datagram: &[u8]) -> (u64, usize) {
        let crate::inbound::InboundFrame::Frame { sn, payload, .. } =
            crate::inbound::parse_inbound(datagram).unwrap()
        else {
            panic!("the datagram is a T_MID_FRAME");
        };
        let messages = crate::network_message::parse_frame_payload(&payload).unwrap();
        (sn, messages.len())
    }

    /// Inside a window the messages of a conduit join one frame: they leave as ONE datagram,
    /// when the window is flushed and not before, carrying ONE sequence number, and room is
    /// asked once, by the message that opened the frame.
    #[test]
    fn messages_in_a_window_leave_as_one_datagram_with_one_sequence_number() {
        let params = params(2_048);
        let conf = TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        );
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Scripted::default();
        let mut window = MulticastBatch::new();
        for payload in [&b"a"[..], b"b", b"c"] {
            let outcome = multicast_tx_push_batched(
                put(true, payload),
                &mut tx,
                &params,
                &conf,
                &mut queue,
                &mut window,
            );
            assert_eq!(outcome, PushOutcome::Pushed);
        }
        assert!(queue.enqueued.is_empty(), "the frame is held open");
        assert_eq!(queue.asks.len(), 1, "room is asked by the opening message");

        window.flush(Priority::DEFAULT, &params, &mut queue);

        assert!(window.is_empty());
        assert_eq!(queue.enqueued.len(), 1, "one datagram");
        assert_eq!(
            frame_of(&queue.enqueued[0]),
            (0, 3),
            "one SN, three messages"
        );
        assert_eq!(
            tx.advertise_default().next_reliable,
            1,
            "the window spent one SN"
        );
    }

    /// An express message takes the window's open frame with it, itself inside it.
    #[test]
    fn an_express_message_takes_the_open_frame_with_it() {
        let params = params(2_048);
        let conf = TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        );
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Scripted::default();
        let mut window = MulticastBatch::new();
        multicast_tx_push_batched(
            put(true, b"a"),
            &mut tx,
            &params,
            &conf,
            &mut queue,
            &mut window,
        );
        assert!(queue.enqueued.is_empty());

        multicast_tx_push_batched(
            express_put(b"now"),
            &mut tx,
            &params,
            &conf,
            &mut queue,
            &mut window,
        );

        assert!(window.is_empty(), "nothing is left open");
        assert_eq!(queue.enqueued.len(), 1);
        assert_eq!(
            frame_of(&queue.enqueued[0]),
            (0, 2),
            "both messages, in the frame"
        );
    }

    /// A message on the other reliability does not join the open frame: the frame leaves, and
    /// the message opens the next frame on its own ring.
    #[test]
    fn a_change_of_reliability_closes_the_open_frame() {
        let params = params(2_048);
        let conf = TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        );
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Scripted::default();
        let mut window = MulticastBatch::new();
        multicast_tx_push_batched(
            put(true, b"a"),
            &mut tx,
            &params,
            &conf,
            &mut queue,
            &mut window,
        );

        multicast_tx_push_batched(
            put(false, b"b"),
            &mut tx,
            &params,
            &conf,
            &mut queue,
            &mut window,
        );

        assert_eq!(queue.enqueued.len(), 1, "the reliable frame left");
        assert_eq!(frame_of(&queue.enqueued[0]), (0, 1));
        assert!(!window.is_empty(), "the best-effort frame is open");
        assert_eq!(tx.advertise_default().next_best_effort, 1);
    }

    /// A message that finds no room leaves nothing on the queue and its
    /// conduit's ring where it was: the next message takes the SN it would
    /// have.
    #[test]
    fn a_message_that_finds_no_room_spends_no_sequence_number() {
        let params = params(2_048);
        let conf = TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        );
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

    /// A producer reads off an item whether it may be dropped, as the push reads it: a
    /// best-effort put may, a blocking terminator may not.
    #[cfg(feature = "codec-response-final")]
    #[test]
    fn a_producer_reads_whether_a_push_may_be_dropped() {
        let params = params(2_048);
        assert!(multicast_tx_droppable(&put(false, b"v"), &params));
        let blocking = crate::sample::QosLevel::from_parts(
            Priority::DEFAULT,
            crate::qos::CongestionControl::Block,
            false,
        );
        let terminal = MulticastTxItem::ResponseFinal {
            request_id: 1,
            qos: blocking,
        };
        assert!(!multicast_tx_droppable(&terminal, &params));
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
            ..TxQueueConf::of_snapshot(
                &crate::policy::SessionPolicy::defaults(),
                &crate::limits::SessionLimits::BUILD,
            )
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
            &TxQueueConf::of_snapshot(
                &crate::policy::SessionPolicy::defaults(),
                &crate::limits::SessionLimits::BUILD,
            ),
            &mut queue,
        );
        assert_eq!(outcome, PushOutcome::Pushed);
        assert_eq!(queue.enqueued, emitted.datagrams);
        assert_eq!(
            crate::sn::to_wire(tx.advertise_default().next_reliable),
            emitted.datagrams.len() as u64
        );
        // Against the whole-chain producer the pre-R2928 emit used.
        let mut whole_tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let sn = whole_tx.mint(Priority::DEFAULT, true);
        let frame = crate::frame_encode::encode_frame_with_push_qos(
            crate::sn::to_wire(sn),
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

    /// A compressing group frames one byte under its batch, for the `BatchHeader` that is
    /// counted inside it; a plain group frames to the whole batch.
    #[test]
    fn a_compressing_group_frames_one_byte_under_its_batch() {
        assert_eq!(params(2_048).frame_budget(), 2_048);
        let squeezing = |batch_size| MulticastParams {
            compression: true,
            ..params(batch_size)
        };
        assert_eq!(squeezing(2_048).frame_budget(), 2_047);
        assert_eq!(squeezing(0).frame_budget(), 0);
        #[cfg(feature = "transport-compression")]
        assert_eq!(
            MulticastParams::BATCH_HEADER_BYTES,
            crate::compression::BATCH_HEADER_BYTES
        );
    }

    /// A compressing group's frame is a batch: the `BatchHeader` in front, the payload lz4-compressed
    /// when that is smaller. What the header and the payload give back is the frame the plain group
    /// sends, on the same sequence number; a frame that does not shrink is sent raw behind a clear
    /// header, one byte longer.
    #[cfg(feature = "transport-compression")]
    #[test]
    fn a_compressing_group_sends_its_frame_as_a_batch() {
        let plain = params(2_048);
        let squeezing = MulticastParams {
            compression: true,
            ..params(2_048)
        };
        let conf = TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        );
        for (payload, shrinks) in [(&[0x5a; 600][..], true), (&b"v"[..], false)] {
            let mut plain_tx = MulticastTxConduits::new(mask_from_res(plain.seq_num_res));
            let mut plain_queue = Scripted::default();
            multicast_tx_push(
                put(true, payload),
                &mut plain_tx,
                &plain,
                &conf,
                &mut plain_queue,
            );
            let mut tx = MulticastTxConduits::new(mask_from_res(squeezing.seq_num_res));
            let mut queue = Scripted::default();
            let outcome =
                multicast_tx_push(put(true, payload), &mut tx, &squeezing, &conf, &mut queue);
            assert_eq!(outcome, PushOutcome::Pushed);
            assert_eq!(queue.enqueued.len(), 1);
            assert_eq!(queue.sns, plain_queue.sns);
            let wire = &queue.enqueued[0];
            let frame = &plain_queue.enqueued[0];
            assert_eq!(
                crate::compression::decompress_batch(wire, 2_048).as_deref(),
                Some(&frame[..])
            );
            let compressed = wire[0] & crate::compression::BATCH_HEADER_COMPRESSION != 0;
            assert_eq!(compressed, shrinks, "payload of {} bytes", payload.len());
            if shrinks {
                assert!(wire.len() < frame.len());
            } else {
                assert_eq!(wire.len(), frame.len() + 1);
            }
            assert_eq!(
                tx.advertise_default().next_reliable,
                plain_tx.advertise_default().next_reliable
            );
        }
    }

    /// A message that fragments does so against the budget a compressing group's header leaves,
    /// so no datagram is past the batch size, header included: the chain is the one a plain group
    /// at that budget sends, each fragment in its batch. A frame that would fit the whole batch
    /// exactly is past the budget and is fragmented too.
    #[cfg(all(feature = "transport-compression", feature = "transport-fragmentation"))]
    #[test]
    fn a_compressing_groups_fragments_fit_the_batch_with_their_header() {
        let squeezing = MulticastParams {
            compression: true,
            ..params(128)
        };
        let conf = TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        );
        // Bytes lz4 cannot shrink, so that a datagram is its header and its fragment.
        let noise = |len: usize| -> Vec<u8> {
            (0..len as u32)
                .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
                .collect()
        };
        let plain_at_budget = params(127);
        let mut payload = noise(1_000);
        let mut plain_tx = MulticastTxConduits::new(mask_from_res(plain_at_budget.seq_num_res));
        let chain = multicast_tx_emit(put(true, &payload), &mut plain_tx, &plain_at_budget);
        assert!(chain.datagrams.len() > 2, "the message fragments");

        let mut tx = MulticastTxConduits::new(mask_from_res(squeezing.seq_num_res));
        let mut queue = Scripted::default();
        let outcome =
            multicast_tx_push(put(true, &payload), &mut tx, &squeezing, &conf, &mut queue);
        assert_eq!(outcome, PushOutcome::Pushed);
        assert_eq!(queue.enqueued.len(), chain.datagrams.len());
        for (wire, fragment) in queue.enqueued.iter().zip(&chain.datagrams) {
            assert!(wire.len() <= 128, "a datagram of {} bytes", wire.len());
            assert_eq!(
                crate::compression::decompress_batch(wire, 128).as_deref(),
                Some(&fragment[..])
            );
        }

        // The payload whose frame is exactly the batch: sent whole by a plain group, and
        // fragmented by a compressing one, which leaves a byte for the header.
        let plain = params(128);
        let exact = (1..127)
            .find(|&len| {
                payload = noise(len);
                let mut tx = MulticastTxConduits::new(mask_from_res(plain.seq_num_res));
                let sent = multicast_tx_emit(put(true, &payload), &mut tx, &plain);
                sent.datagrams.len() == 1 && sent.datagrams[0].len() == 128
            })
            .expect("a payload whose frame is exactly the batch");
        assert_eq!(payload.len(), exact);
        let mut tx = MulticastTxConduits::new(mask_from_res(squeezing.seq_num_res));
        let mut queue = Scripted::default();
        multicast_tx_push(put(true, &payload), &mut tx, &squeezing, &conf, &mut queue);
        assert!(
            queue.enqueued.len() > 1,
            "the whole frame is past the budget"
        );
        assert!(queue.enqueued.iter().all(|wire| wire.len() <= 128));
    }

    /// A chain that finds no room part-way is stopped: the fragments already
    /// out, then a drop marker on the next SN, which it spends. Each further
    /// ask carries the extended deadline, doubling per fragment.
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn a_chain_that_runs_out_part_way_ends_with_a_drop_marker_on_the_next_sn() {
        use crate::inbound::{parse_inbound, InboundFrame};
        let params = params(128);
        let conf = TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        );
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
        let conf = TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        );
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
            &TxQueueConf::of_snapshot(
                &crate::policy::SessionPolicy::defaults(),
                &crate::limits::SessionLimits::BUILD,
            ),
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
            whatami: WhatAmI::Peer,
            zid: crate::session_zid::SessionZid::from_array([1, 2, 3, 4]),
            lease_ms: 5_000,
            join_interval_ms: 50,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size,
            is_qos,
            compression: false,
            tx_queue: TxQueueConf::of_snapshot(
                &crate::policy::SessionPolicy::defaults(),
                &crate::limits::SessionLimits::BUILD,
            ),
            link_rx: crate::session_init_params::LinkRxConf::default(),
            join_rule: crate::multicast_params::GroupJoinRule::Pico,
            max_sessions: None,
            policy: crate::policy::SessionPolicy::defaults(),
            limits: crate::limits::SessionLimits::BUILD,
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
        /// How many more asks for room are answered with room.
        room_left: usize,
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
                room_left: usize::MAX,
            }
        }
    }

    impl MulticastTxQueue for Lending {
        fn wait_for_room(&mut self, _priority: Priority, _wait: RoomWait) -> RoomAnswer {
            if self.room_left == 0 {
                return RoomAnswer::at_once(LinkRoom::Congested);
            }
            self.room_left -= 1;
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
                &TxQueueConf::of_snapshot(
                    &crate::policy::SessionPolicy::defaults(),
                    &crate::limits::SessionLimits::BUILD,
                ),
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
            &TxQueueConf::of_snapshot(
                &crate::policy::SessionPolicy::defaults(),
                &crate::limits::SessionLimits::BUILD,
            ),
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

    /// A frame past the group's batch is cut into a chain whose every fragment is written into a
    /// slot of its own: the very chain the emit returns, its SNs ring-consecutive from the one
    /// minted for the frame, and nothing built on the heap.
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn a_frame_past_the_batch_is_fragmented_into_lent_slots() {
        let params = params(256, false);
        let payload = [0xA5u8; 1_000];
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Lending::new(1_472, 65_600);
        multicast_tx_push(
            put(&payload, Priority::DEFAULT),
            &mut tx,
            &params,
            &TxQueueConf::of_snapshot(
                &crate::policy::SessionPolicy::defaults(),
                &crate::limits::SessionLimits::BUILD,
            ),
            &mut queue,
        );
        assert!(queue.heap.is_empty(), "no fragment was built on the heap");
        let chain: Vec<Vec<u8>> = queue.lent.iter().map(|(_, b, _)| b.clone()).collect();
        assert!(chain.len() > 2, "the message fragments");
        assert_eq!(chain, emitted(put(&payload, Priority::DEFAULT), &params));
        let sns: Vec<u64> = queue.lent.iter().map(|(_, _, sn)| *sn).collect();
        assert_eq!(sns, (0..chain.len() as u64).collect::<Vec<_>>());
    }

    /// A lent chain that finds no room before a fragment stops with the drop marker, itself
    /// written into a lent slot on the SN the fragment would have taken, and is a congestion drop.
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn a_lent_chain_out_of_room_ends_with_a_lent_drop_marker() {
        let params = params(256, false);
        let payload = [0xA5u8; 1_000];
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Lending::new(1_472, 65_600);
        // The frame's ask and the second fragment's are answered with room, the third's not.
        queue.room_left = 2;
        let outcome = multicast_tx_push(
            put(&payload, Priority::DEFAULT),
            &mut tx,
            &params,
            &TxQueueConf::of_snapshot(
                &crate::policy::SessionPolicy::defaults(),
                &crate::limits::SessionLimits::BUILD,
            ),
            &mut queue,
        );
        assert_eq!(outcome, PushOutcome::Congested);
        assert!(queue.heap.is_empty());
        let sns: Vec<u64> = queue.lent.iter().map(|(_, _, sn)| *sn).collect();
        assert_eq!(sns, [0, 1, 2], "two fragments and the marker");
        let (_, marker, _) = queue.lent.last().expect("the marker");
        assert!(marker.len() < 16, "the marker carries no payload");
    }

    /// A queue that lends a slot longer than the batch: the frame is held to the batch in it, so a
    /// frame past the batch is refused before its payload is copied in, and leaves as a chain.
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn a_slot_longer_than_the_batch_holds_the_frame_to_the_batch() {
        struct Oversized {
            /// The bytes each lent slot was left holding past the length asked for.
            past_want: Vec<usize>,
            lent: usize,
        }
        impl MulticastTxQueue for Oversized {
            fn wait_for_room(&mut self, _priority: Priority, _wait: RoomWait) -> RoomAnswer {
                RoomAnswer::at_once(LinkRoom::Free)
            }
            fn enqueue(&mut self, _datagram: MulticastTxDatagram) {}
            fn enqueue_lent(
                &mut self,
                _priority: Priority,
                _reliable: bool,
                _sn: u64,
                want: usize,
                fill: &mut dyn FnMut(&mut SliceTxBuf<'_>) -> bool,
            ) -> bool {
                let mut storage = alloc::vec![0u8; want * 4];
                let filled = fill(&mut SliceTxBuf::new(&mut storage));
                let past = storage.get(want..).unwrap_or_default();
                self.past_want
                    .push(past.iter().filter(|b| **b != 0).count());
                self.lent += usize::from(filled);
                filled
            }
        }
        let params = params(256, false);
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Oversized {
            past_want: Vec::new(),
            lent: 0,
        };
        let outcome = multicast_tx_push(
            put(&[0xA5u8; 1_000], Priority::DEFAULT),
            &mut tx,
            &params,
            &TxQueueConf::of_snapshot(
                &crate::policy::SessionPolicy::defaults(),
                &crate::limits::SessionLimits::BUILD,
            ),
            &mut queue,
        );
        assert_eq!(outcome, PushOutcome::Pushed);
        assert!(
            queue.lent > 2,
            "the frame left as a chain of lent fragments"
        );
        assert_eq!(
            queue.past_want.first(),
            Some(&0),
            "the whole frame was refused at the batch: nothing written past it"
        );
    }

    /// A window's frame is held to the batch in the window's own storage: a message that would
    /// carry it past the batch is refused before it is written, the storage does not grow, and a
    /// frame handed to a queue that lends nothing is a copy of exactly the frame, the storage
    /// staying the window's.
    #[test]
    fn a_window_holds_its_frame_to_the_batch_in_storage_of_its_own() {
        use sce_forge_runtime::codec::SceSink;
        let budget = 64;
        let params = params(64, false);
        let mut window = MulticastBatch::with_budget(budget);
        let storage = window.buf.capacity();
        assert!(window.open_with(true, 3, budget, |buf| {
            crate::tx_buf::TxSink::new(buf)
                .write_bytes(&[9u8; 10])
                .is_ok()
        }));
        let twenty = |sink: &mut crate::tx_buf::TxSink<'_>| sink.write_bytes(&[1u8; 20]);
        assert!(window.append(true, budget, &twenty));
        assert!(window.append(true, budget, &twenty));
        assert!(
            !window.append(true, budget, &twenty),
            "seventy bytes are past the batch"
        );
        assert_eq!(
            window.frame().len(),
            50,
            "the refused message left the frame as it was"
        );
        assert_eq!(
            window.buf.capacity(),
            storage,
            "the refused message was not written into a grown vector"
        );
        assert!(
            window
                .buf
                .get(50..)
                .unwrap_or_default()
                .iter()
                .all(|b| *b == 0),
            "nothing of the refused message was written"
        );
        assert!(
            !window.append(false, budget, &twenty),
            "another channel does not join the frame"
        );

        // A queue that lends no slot (a zero-length one is refused) is handed the frame.
        let mut queue = Lending::new(0, 0);
        window.flush(Priority::DEFAULT, &params, &mut queue);
        assert!(window.is_empty());
        let mut frame = alloc::vec![9u8; 10];
        frame.extend_from_slice(&[1u8; 40]);
        assert_eq!(queue.heap, alloc::vec![(frame, 3)], "exactly the frame");
        assert_eq!(
            window.buf.capacity(),
            storage,
            "the storage stayed the window's"
        );

        // A frame held whole is past the batch: nothing is appended to it, and it is handed over
        // as it is.
        let whole = alloc::vec![5u8; budget * 2];
        window.hold(true, 4, whole.clone());
        assert!(!window.append(true, budget, &twenty));
        window.flush(Priority::DEFAULT, &params, &mut queue);
        assert_eq!(queue.heap.last(), Some(&(whole, 4)));
    }

    /// A batch window's frame is written into the window's own storage and leaves through a lent
    /// slot when the window is flushed: one datagram carrying both messages, nothing on the heap,
    /// and the window keeps its storage for the next frame.
    #[test]
    fn a_window_frame_leaves_through_a_lent_slot() {
        let params = params(8_192, false);
        let conf = TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        );
        let mut tx = MulticastTxConduits::new(mask_from_res(params.seq_num_res));
        let mut queue = Lending::new(1_472, 65_600);
        let mut window = MulticastBatch::with_budget(params.frame_budget());
        for payload in [&b"one"[..], &b"two"[..]] {
            let outcome = multicast_tx_push_batched(
                put(payload, Priority::DEFAULT),
                &mut tx,
                &params,
                &conf,
                &mut queue,
                &mut window,
            );
            assert_eq!(outcome, PushOutcome::Pushed);
        }
        assert!(
            queue.lent.is_empty() && queue.heap.is_empty(),
            "the window holds both"
        );
        window.flush(Priority::DEFAULT, &params, &mut queue);
        assert!(queue.heap.is_empty(), "nothing was handed over on the heap");
        assert_eq!(queue.lent.len(), 1, "one frame for both");
        assert!(queue.lent[0].1.ends_with(b"two"));
        assert!(window.is_empty());
        assert!(
            window.buf.capacity() >= params.frame_budget(),
            "its storage is kept"
        );
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
                &TxQueueConf::of_snapshot(
                    &crate::policy::SessionPolicy::defaults(),
                    &crate::limits::SessionLimits::BUILD,
                ),
                &mut queue,
            );
        }
        let sns: Vec<u64> = queue.lent.iter().map(|(_, _, sn)| *sn).collect();
        assert_eq!(sns, [0, 1, 2]);
        assert_eq!(tx.advertise_default().next_reliable, 3);
    }
}

/// The TX of a build with no allocator, held against the heap emit it replaces: the
/// same bytes on the wire and the same walk of the SN ring, in one build that has both.
#[cfg(all(
    test,
    feature = "alloc",
    feature = "codec-push",
    feature = "transport-tx-lend"
))]
mod lent_emit_tests {
    use super::*;
    use crate::multicast_params::MulticastParams;
    use crate::sn::{mask_from_res, MulticastTxConduits};
    use crate::WhatAmI;

    fn params(batch_size: u16, is_qos: bool) -> MulticastParams {
        MulticastParams {
            whatami: WhatAmI::Peer,
            zid: crate::session_zid::SessionZid::from_array([1, 2, 3, 4]),
            lease_ms: 5_000,
            join_interval_ms: 50,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size,
            is_qos,
            compression: false,
            tx_queue: TxQueueConf::of_snapshot(
                &crate::policy::SessionPolicy::defaults(),
                &crate::limits::SessionLimits::BUILD,
            ),
            link_rx: crate::session_init_params::LinkRxConf::default(),
            join_rule: crate::multicast_params::GroupJoinRule::Pico,
            max_sessions: None,
            policy: crate::policy::SessionPolicy::defaults(),
            limits: crate::limits::SessionLimits::BUILD,
        }
    }

    fn conduits(params: &MulticastParams) -> MulticastTxConduits {
        MulticastTxConduits::new(mask_from_res(params.seq_num_res))
    }

    /// The datagrams the lent emit sends for `put`, in order, and what it answered.
    fn lent(
        put: &MulticastTxPut<'_>,
        tx: &mut MulticastTxConduits,
        params: &MulticastParams,
        scratch: &mut [u8],
    ) -> (Vec<Vec<u8>>, Result<usize, MulticastTxRefused>) {
        let mut sent = Vec::new();
        let answer = multicast_tx_emit_lent(put, tx, params, scratch, &mut |datagram| {
            sent.push(datagram.to_vec());
        });
        (sent, answer)
    }

    /// For a Put that fits the batch, and (where the build fragments) for one that does
    /// not, on both channels and with and without a QoS band: the datagrams are the heap
    /// emit's byte for byte, and the ring stands where the heap emit leaves it, so the
    /// next beacon advertises the same `next_*`.
    #[test]
    fn the_lent_emit_is_the_heap_emit_byte_for_byte() {
        let mut compared = 0usize;
        for batch_size in [64u16, 2_048] {
            for payload_len in [0usize, 1, 20, 200] {
                // Past the batch a build without fragmentation sends the frame whole
                // from the heap and refuses it lent: not a pair to compare.
                let fragments = payload_len + 16 > usize::from(batch_size);
                if fragments && !cfg!(feature = "transport-fragmentation") {
                    continue;
                }
                for reliable in [true, false] {
                    for (is_qos, priority) in
                        [(false, Priority::DEFAULT), (true, Priority::RealTime)]
                    {
                        let params = params(batch_size, is_qos);
                        let payload: Vec<u8> = (0..payload_len)
                            .map(|i| (i as u8).wrapping_mul(7))
                            .collect();
                        let put = MulticastTxPut {
                            keyexpr: "demo/mc",
                            payload: &payload,
                            reliable,
                            priority,
                        };
                        let mut heap_tx = conduits(&params);
                        let item = MulticastTxItem::Push {
                            push: Box::new(
                                crate::push_build::build_push_literal("demo/mc", &payload)
                                    .expect("a literal Put builds"),
                            ),
                            reliable,
                            priority,
                        };
                        let heap = multicast_tx_emit(item, &mut heap_tx, &params).datagrams;

                        let mut lent_tx = conduits(&params);
                        let mut scratch = [0u8; 1_472];
                        let (sent, answer) = lent(&put, &mut lent_tx, &params, &mut scratch);

                        let what = alloc::format!(
                            "batch {batch_size}, {payload_len} bytes, reliable {reliable}, \
                             qos {is_qos}"
                        );
                        assert_eq!(answer, Ok(heap.len()), "{what}");
                        assert_eq!(sent, heap, "{what}");
                        assert_eq!(
                            lent_tx.mint(priority, reliable),
                            heap_tx.mint(priority, reliable),
                            "the ring stands where the heap emit leaves it: {what}"
                        );
                        compared += 1;
                    }
                }
            }
        }
        assert!(compared >= 16, "the sweep compared {compared} cases");
    }

    /// A buffer too small to hold even a fragment's head refuses the Put and sends
    /// nothing: no truncated datagram ever reaches the wire.
    #[test]
    fn a_buffer_too_small_for_a_datagram_sends_nothing() {
        let params = params(64, false);
        let payload = [0x55u8; 200];
        let put = MulticastTxPut::literal("demo/mc", &payload);
        let mut tx = conduits(&params);
        let mut scratch = [0u8; 1];
        let (sent, answer) = lent(&put, &mut tx, &params, &mut scratch);
        assert!(answer.is_err(), "refused, got {answer:?}");
        assert!(sent.is_empty(), "nothing was sent: {sent:?}");
    }

    /// The offer seam of the heap profile is the heap emit: one call, the same datagrams.
    #[test]
    fn the_offer_seam_of_a_heap_build_is_the_heap_emit() {
        let params = params(64, false);
        let payload = [0xA5u8; 120];
        let offer = multicast_tx_offer_put_literal("demo/mc", &payload).expect("builds");
        let mut via_offer = conduits(&params);
        let mut sent = Vec::new();
        let count = multicast_tx_emit_offer(offer, &mut via_offer, &params, &mut [], &mut |d| {
            sent.push(d.to_vec())
        });
        let mut direct = conduits(&params);
        let heap = multicast_tx_emit(
            multicast_put_literal("demo/mc", &payload).expect("builds"),
            &mut direct,
            &params,
        )
        .datagrams;
        assert_eq!(count, heap.len());
        assert_eq!(sent, heap);
    }
}

/// A group's declaration written from its parts is the bytes its owned builder builds, framed as the
/// owned one is.
#[cfg(all(
    test,
    feature = "alloc",
    feature = "codec-push",
    feature = "codec-declare"
))]
mod group_declarations_written_from_parts {
    use super::*;
    use crate::declare_form::{GroupDeclaration, GroupKey};

    /// The bytes `body` writes.
    fn written(body: &crate::frame_encode::BodyEncoder<'_>) -> Vec<u8> {
        let mut bytes = Vec::new();
        body(&mut crate::tx_buf::TxSink::new(&mut bytes)).expect("written");
        bytes
    }

    /// Every kind this build has a declaration plane of.
    fn kinds() -> Vec<GroupDeclaration> {
        Vec::from([
            #[cfg(feature = "declare-subscriber")]
            GroupDeclaration::Subscriber,
            #[cfg(feature = "declare-queryable")]
            GroupDeclaration::Queryable { complete: true },
            #[cfg(feature = "declare-queryable")]
            GroupDeclaration::Queryable { complete: false },
            #[cfg(feature = "liveliness-token")]
            GroupDeclaration::Token,
        ])
    }

    /// The keys a group names: a literal, an alias with a suffix, an alias alone, and a multi-byte
    /// id.
    fn keys() -> [GroupKey<'static>; 4] {
        [
            GroupKey {
                mapping_id: 0,
                suffix: Some("demo/group/a"),
            },
            GroupKey {
                mapping_id: 7,
                suffix: Some("/**"),
            },
            GroupKey {
                mapping_id: 7,
                suffix: None,
            },
            GroupKey {
                mapping_id: 300,
                suffix: Some("/x"),
            },
        ]
    }

    /// A retraction written from its parts is `build_group_retraction`'s bytes (the
    /// `build_undeclare_*_on_wire` form, the key in its `ext_keyexpr`), counted as long as it is,
    /// and framed as a declaration. Turned red by a retraction that names its key apart from the
    /// owned one, or by one that drops the key.
    #[test]
    fn a_group_retraction_written_from_its_parts_is_its_builders_bytes() {
        let mut compared = 0usize;
        for what in kinds() {
            for key in keys() {
                let owned = crate::declare_build::build_group_retraction(what, 5, key)
                    .expect("an owned retraction");
                let expected = written(&|sink: &mut crate::tx_buf::TxSink<'_>| owned.encode(sink));
                let (bytes, size, framing) = multicast_tx_group_retraction(what, 5, key, |m| {
                    (written(m.body), m.size, m.framing)
                })
                .expect("a retraction written from its parts");
                assert_eq!(bytes, expected, "{what:?} on {key:?}");
                assert_eq!(size, expected.len());
                assert_eq!(
                    framing,
                    MulticastTxFraming::Control {
                        qos: crate::declare_ext_qos::read_declare_qos(&owned),
                    }
                );
                compared += 1;
            }
        }
        assert_eq!(compared, kinds().len() * keys().len());
    }

    /// An announcement written from its parts is `build_group_announcement`'s bytes. Turned red by a
    /// writer that announces another id, key or queryable info than the owned builder.
    #[test]
    fn a_group_announcement_written_from_its_parts_is_its_builders_bytes() {
        let mut compared = 0usize;
        for what in kinds() {
            for key in keys() {
                let owned = crate::declare_build::build_group_announcement(what, 5, key)
                    .expect("an owned announcement");
                let expected = written(&|sink: &mut crate::tx_buf::TxSink<'_>| owned.encode(sink));
                let bytes = multicast_tx_group_announcement(what, 5, key, |m| written(m.body))
                    .expect("an announcement written from its parts");
                assert_eq!(bytes, expected, "{what:?} on {key:?}");
                compared += 1;
            }
        }
        assert_eq!(compared, kinds().len() * keys().len());
    }

    /// The answer to a member's interest in tokens, written from the borrowed reply, is the bytes
    /// of the owned reply a backing that queues owned items builds, counted as long as it is and
    /// framed as that one is; a keyexpr past the protocol's bound is refused with `f` not called.
    /// Turned red by a writer that answers with another header, id or key than the owned reply, a
    /// size that is not its length, or a framing that reads another QoS than the owned reply's.
    #[cfg(feature = "liveliness-token")]
    #[test]
    fn a_token_reply_written_from_the_borrowed_reply_is_the_owned_replys_bytes() {
        let long = "k".repeat(300);
        let cases: [(u64, &str, u64); 3] = [
            (0, "demo/token", 0),
            (9, "demo/**", 42),
            (300, long.as_str(), 70_000),
        ];
        for (token_id, keyexpr, interest_id) in cases {
            let owned =
                crate::declare::local_token::build_token_reply(token_id, keyexpr, interest_id)
                    .and_then(|reply| {
                        reply.try_into_owned_in::<crate::transport_profile::TransportStorage>()
                    })
                    .expect("an owned reply");
            let expected = written(&|sink: &mut crate::tx_buf::TxSink<'_>| owned.encode(sink));
            let (bytes, size, framing) =
                multicast_tx_token_reply(token_id, keyexpr, interest_id, |m| {
                    (written(m.body), m.size, m.framing)
                })
                .expect("a reply written from the borrowed one");
            assert_eq!(bytes, expected, "token {token_id} on {keyexpr}");
            assert_eq!(size, expected.len());
            assert_eq!(
                framing,
                MulticastTxFraming::Control {
                    qos: crate::declare_ext_qos::read_declare_qos(&owned),
                }
            );
        }
        let past = "k".repeat(usize::from(u16::MAX) + 1);
        let mut called = false;
        assert!(multicast_tx_token_reply(1, &past, 2, |_| called = true).is_none());
        assert!(!called, "a refused reply is handed to nobody");
    }

    /// A declaration written from its parts is counted as the owned one is, a control message of
    /// the declare kind on the band of its own QoS with no payload; so is the answer to a member's
    /// interest in tokens, and an interest is one of the interest kind on the default band. Turned
    /// red by a lent control message counted as another kind or on another band.
    #[cfg(feature = "transport-stats")]
    #[test]
    fn a_control_message_written_from_its_parts_is_counted_by_its_kind() {
        use crate::stats::{MessageLabel, NetworkStatsClass};
        let declare = NetworkStatsClass::control(MessageLabel::Declare);
        let mut compared = 0usize;
        for what in kinds() {
            for key in keys() {
                let owned = crate::declare_build::build_group_announcement(what, 5, key)
                    .expect("an owned announcement");
                let tally = multicast_tx_group_announcement(what, 5, key, |m| m.tally)
                    .expect("an announcement written from its parts");
                assert_eq!(
                    (tally.priority(), *tally.class()),
                    (
                        crate::declare_ext_qos::read_declare_qos(&owned).priority(),
                        declare
                    ),
                    "{what:?} on {key:?}"
                );
                compared += 1;
            }
        }
        assert_eq!(compared, kinds().len() * keys().len());

        let interest = crate::lent_control::interest_final(9);
        let tally = multicast_tx_interest(&interest, |m| m.tally).expect("an interest");
        assert_eq!(
            (tally.priority(), *tally.class()),
            (
                Priority::DEFAULT,
                NetworkStatsClass::control(MessageLabel::Interest)
            )
        );

        #[cfg(feature = "liveliness-token")]
        {
            let tally =
                multicast_tx_token_reply(9, "demo/token", 42, |m| m.tally).expect("a reply");
            assert_eq!(
                (tally.priority(), *tally.class()),
                (Priority::DEFAULT, declare)
            );
        }
    }
}

/// A group's publication written from its parts is the bytes of the owned Push the group would
/// have built for it, named as the group's publish names its key.
#[cfg(all(test, feature = "alloc", feature = "codec-push"))]
mod group_publications_written_from_parts {
    use super::*;
    use crate::metadata::PushMetadata;
    use crate::push_build;
    use crate::sample::SampleKind;

    /// The bytes `body` writes.
    fn written(body: &crate::frame_encode::BodyEncoder<'_>) -> Vec<u8> {
        let mut bytes = Vec::new();
        body(&mut crate::tx_buf::TxSink::new(&mut bytes)).expect("written");
        bytes
    }

    /// The publication written from `(mapping_id, suffix)`, as the group's publish writes it.
    fn lent(
        mapping_id: crate::wire_id::ExprId,
        suffix: Option<&str>,
        kind: SampleKind,
        meta: &PushMetadata,
    ) -> Vec<u8> {
        multicast_tx_publication(
            crate::declare_form::GroupKey { mapping_id, suffix },
            kind,
            b"value",
            meta,
            true,
            Priority::DEFAULT,
            |message| written(message.body),
        )
        .expect("written from its parts")
    }

    /// A literal key, named `(0, Some(keyexpr))` as the group's publish names it, and an aliased
    /// one, each a Put and a Del, plain and with metadata, are the owned builders' bytes. Turned
    /// red by a literal named another way than the owned literal Push names it.
    #[test]
    fn a_group_publication_written_from_its_parts_is_its_builders_bytes() {
        #[cfg_attr(not(feature = "pubsub-qos"), allow(unused_mut))]
        let mut metas = alloc::vec![
            PushMetadata::default(),
            PushMetadata {
                attachment: Some(&[1, 2, 3]),
                ..PushMetadata::default()
            },
        ];
        #[cfg(feature = "pubsub-qos")]
        metas.push(PushMetadata {
            qos: Some(
                crate::sample::QosLevel::DEFAULT
                    .with_congestion(crate::qos::CongestionControl::Drop),
            ),
            ..PushMetadata::default()
        });
        let mut compared = 0usize;
        for meta in &metas {
            let literal_put =
                push_build::build_push_literal_with_meta("demo/group", b"value", meta)
                    .expect("put");
            let literal_del =
                push_build::build_push_del_literal_with_meta("demo/group", meta).expect("del");
            let aliased_put =
                push_build::build_push_aliased_with_meta(7, Some("/x"), b"value", meta)
                    .expect("aliased put");
            let aliased_del = push_build::build_push_del_aliased_with_meta(7, Some("/x"), meta)
                .expect("aliased del");
            let owned =
                |push: &crate::wire::PushOwned| written(&crate::frame_encode::push_body(push));
            assert_eq!(
                lent(0, Some("demo/group"), SampleKind::Put, meta),
                owned(&literal_put)
            );
            assert_eq!(
                lent(0, Some("demo/group"), SampleKind::Del, meta),
                owned(&literal_del)
            );
            assert_eq!(
                lent(7, Some("/x"), SampleKind::Put, meta),
                owned(&aliased_put)
            );
            assert_eq!(
                lent(7, Some("/x"), SampleKind::Del, meta),
                owned(&aliased_del)
            );
            compared += 4;
        }
        assert_eq!(compared, metas.len() * 4);
    }

    /// The band and the class a tally holds.
    #[cfg(feature = "transport-stats")]
    fn read(tally: &MulticastTxTally) -> (Priority, crate::stats::NetworkStatsClass) {
        (tally.priority(), *tally.class())
    }

    /// What the publication written from `(mapping_id, suffix)` on the band `DataHigh` is counted
    /// as.
    #[cfg(feature = "transport-stats")]
    fn lent_tally(
        mapping_id: crate::wire_id::ExprId,
        suffix: Option<&str>,
        kind: SampleKind,
        meta: &PushMetadata<'_>,
    ) -> (Priority, crate::stats::NetworkStatsClass) {
        multicast_tx_publication(
            crate::declare_form::GroupKey { mapping_id, suffix },
            kind,
            b"value",
            meta,
            true,
            Priority::DataHigh,
            |message| read(&message.tally),
        )
        .expect("written from its parts")
    }

    /// What the owned `push` queued on the band `DataHigh` is counted as.
    #[cfg(feature = "transport-stats")]
    fn owned_tally(push: crate::wire::PushOwned) -> (Priority, crate::stats::NetworkStatsClass) {
        read(&MulticastTxTally::of(&MulticastTxItem::Push {
            push: Box::new(push),
            reliable: true,
            priority: Priority::DataHigh,
        }))
    }

    /// A publication written from its parts is counted as the owned Push of the same parts is: on
    /// the band its publisher chose, by its kind, the space of its key, and its payload with its
    /// attachment, a Del by its attachment alone. Turned red by a lent class read off other parts
    /// than the owned one's: a Del sized by its value, an attachment left out, an admin key read
    /// as a user one.
    #[cfg(feature = "transport-stats")]
    #[test]
    fn a_group_publication_written_from_its_parts_is_counted_as_its_owned_push() {
        use crate::stats::{MessageLabel, NetworkStatsClass, StatMessage, StatSpace};
        let attached = PushMetadata {
            attachment: Some(&[1, 2, 3]),
            ..PushMetadata::default()
        };
        let plain = PushMetadata::default();
        let mut compared = 0usize;
        for meta in [&plain, &attached] {
            for keyexpr in ["demo/group", "@/group"] {
                let put =
                    push_build::build_push_literal_with_meta(keyexpr, b"value", meta).expect("put");
                let del = push_build::build_push_del_literal_with_meta(keyexpr, meta).expect("del");
                assert_eq!(
                    lent_tally(0, Some(keyexpr), SampleKind::Put, meta),
                    owned_tally(put)
                );
                assert_eq!(
                    lent_tally(0, Some(keyexpr), SampleKind::Del, meta),
                    owned_tally(del)
                );
                compared += 2;
            }
            let put = push_build::build_push_aliased_with_meta(7, Some("/x"), b"value", meta)
                .expect("aliased put");
            let del = push_build::build_push_del_aliased_with_meta(7, Some("/x"), meta)
                .expect("aliased del");
            assert_eq!(
                lent_tally(7, Some("/x"), SampleKind::Put, meta),
                owned_tally(put)
            );
            assert_eq!(
                lent_tally(7, Some("/x"), SampleKind::Del, meta),
                owned_tally(del)
            );
            compared += 2;
        }
        assert_eq!(compared, 12);
        // The cells themselves, so that a rule both readings got wrong alike is caught too: the
        // attachment counts where the build writes it.
        let attachment = if cfg!(feature = "pubsub-attachment") {
            3
        } else {
            0
        };
        assert_eq!(
            lent_tally(0, Some("@/group"), SampleKind::Put, &attached),
            (
                Priority::DataHigh,
                NetworkStatsClass::net(
                    MessageLabel::Put,
                    StatMessage::Put,
                    StatSpace::Admin,
                    "value".len() + attachment
                )
            )
        );
        assert_eq!(
            lent_tally(7, Some("/x"), SampleKind::Del, &attached),
            (
                Priority::DataHigh,
                NetworkStatsClass::net(
                    MessageLabel::Del,
                    StatMessage::Del,
                    StatSpace::User,
                    attachment
                )
            )
        );
    }
}

/// A get written from its parts is counted as the owned `Request` of the same parts is.
#[cfg(all(
    test,
    feature = "transport-stats",
    feature = "codec-push",
    feature = "codec-request"
))]
mod lent_get_tallies {
    use super::*;
    use crate::query_parts::{GetParts, QueryParts};
    use crate::reply_stage::EncodingParts;
    use crate::wire_key::WireKey;

    /// Every key form, a get with no value, with a value under the zero encoding and under one
    /// with a schema, with and without an attachment, on two bands: the lent tally is the owned
    /// `Request`'s, a query counted by its value's payload and its attachment. Turned red by a
    /// value counted with its encoding, an attachment left out, a key read into another space, or
    /// a band other than the query's own.
    #[test]
    fn a_get_written_from_its_parts_is_counted_as_its_owned_request() {
        use crate::stats::{MessageLabel, NetworkStatsClass, StatMessage, StatSpace};
        let keys = [
            WireKey::literal("demo/**").expect("a literal"),
            WireKey::literal("@/demo").expect("a literal"),
            WireKey::from_parts(300, Some("/tail")).expect("an id and a suffix"),
        ];
        let values: [Option<(EncodingParts<'_>, &[u8])>; 3] = [
            None,
            Some((
                EncodingParts {
                    packed_id: 0,
                    schema: None,
                },
                b"payload",
            )),
            Some((
                EncodingParts {
                    packed_id: 0x0B,
                    schema: Some(b"json"),
                },
                b"{}",
            )),
        ];
        let attachments: [&[u8]; 2] = [b"", b"attached"];
        let bands = [
            crate::sample::QosLevel::DEFAULT,
            crate::declare_ext_qos::QOS_DECLARE,
        ];
        let tally_of = |parts: GetParts<'_>| {
            let writer = crate::lent_request::RequestWriter::new(parts);
            multicast_tx_request(&writer, parts.query.qos, |m| {
                (m.tally.priority(), *m.tally.class())
            })
            .expect("written from its parts")
        };
        let mut compared = 0usize;
        for key in keys {
            for value in values {
                for attachment in attachments {
                    for qos in bands {
                        let parts = GetParts {
                            rid: 7,
                            key,
                            query: QueryParts {
                                value,
                                attachment,
                                qos,
                                ..QueryParts::PLAIN
                            },
                        };
                        let owned = MulticastTxTally::of(&MulticastTxItem::Request {
                            request: Box::new(parts.owned_request().expect("built")),
                        });
                        assert_eq!(
                            tally_of(parts),
                            (owned.priority(), *owned.class()),
                            "{parts:?}"
                        );
                        compared += 1;
                    }
                }
            }
        }
        assert_eq!(compared, 3 * 3 * 2 * 2);
        // The cell itself, so that a rule both readings got wrong alike is caught too: the value
        // and the attachment count where the build writes them.
        let value = if cfg!(feature = "query-value") {
            "payload".len()
        } else {
            0
        };
        let attachment = if cfg!(feature = "query-attachment") {
            "attached".len()
        } else {
            0
        };
        let admin = GetParts {
            rid: 7,
            key: WireKey::literal("@/demo").expect("a literal"),
            query: QueryParts {
                value: values[1],
                attachment: b"attached",
                ..QueryParts::PLAIN
            },
        };
        assert_eq!(
            tally_of(admin),
            (
                crate::sample::QosLevel::DEFAULT.priority(),
                NetworkStatsClass::net(
                    MessageLabel::Query,
                    StatMessage::Query,
                    StatSpace::Admin,
                    value + attachment
                )
            )
        );
    }
}

/// A reply a group's dispatch stages is counted as its owned record is, whichever form it is
/// handed in.
#[cfg(all(test, feature = "transport-stats", feature = "codec-response"))]
mod reply_tallies {
    use super::*;
    use crate::qos::CongestionControl;
    use crate::reply_stage::{PartsBody, PartsKind, ReplyParts};
    use crate::sample::QosLevel;
    use crate::stats::{MessageLabel, NetworkStatsClass, StatMessage, StatSpace};

    /// The band and the class a tally holds.
    fn read(tally: &MulticastTxTally) -> (Priority, NetworkStatsClass) {
        (tally.priority(), *tally.class())
    }

    /// What the owned `Response` the parts build is counted as, queued as the item a backing
    /// that keeps owned replies queues.
    fn owned(parts: &ReplyParts<'_>) -> (Priority, NetworkStatsClass) {
        let response = crate::query::QueryReply::from_parts(parts)
            .into_response()
            .expect("the owned reply");
        read(&MulticastTxTally::of(&MulticastTxItem::Response {
            response: Box::new(response),
        }))
    }

    /// A reply's parts: of `body` with `attachment`, stamped with `keyexpr`, on the band
    /// `DataHigh`.
    fn parts<'a>(
        keyexpr: &'a str,
        body: PartsBody<'a>,
        attachment: Option<&'a [u8]>,
    ) -> ReplyParts<'a> {
        ReplyParts::new(
            9,
            keyexpr,
            Some((&[1, 2, 3, 4], 5)),
            QosLevel::from_parts(Priority::DataHigh, CongestionControl::Block, false),
            PartsKind::Reply {
                body,
                encoding: None,
                timestamp: None,
                attachment,
                source_info: None,
            },
        )
    }

    /// A reply written from its parts is counted as the owned `Response` the same parts build: a
    /// Put by its payload and attachment, a Del by its attachment, each in its key's space and on
    /// its own band; and a reply handed as its owned record is counted as the item it copies to.
    /// Turned red by a lent reply counted by other bytes, in another space or on another band than
    /// the owned one, or a lent record whose tally is not its item's.
    #[test]
    fn a_reply_written_from_its_parts_is_counted_as_its_owned_response() {
        let mut compared = 0usize;
        for keyexpr in ["demo/a", "@/a"] {
            for body in [PartsBody::Put(b"answer"), PartsBody::Del] {
                for attachment in [None, Some(&b"att"[..])] {
                    let parts = parts(keyexpr, body, attachment);
                    let expected = owned(&parts);
                    assert_eq!(
                        read(&MulticastTxTally::of_reply_parts(&parts)),
                        expected,
                        "{keyexpr}"
                    );
                    let response = crate::query::QueryReply::from_parts(&parts)
                        .into_response()
                        .expect("the owned reply");
                    let lent = MulticastTxReply::Response(&response);
                    assert_eq!(
                        read(&lent.tally()),
                        read(&MulticastTxTally::of(&lent.to_item()))
                    );
                    compared += 1;
                }
            }
        }
        assert_eq!(compared, 2 * 2 * 2);
        // The cell itself, so that a rule both readings got wrong alike is caught too.
        let attachment = if cfg!(feature = "pubsub-attachment") {
            3
        } else {
            0
        };
        assert_eq!(
            read(&MulticastTxTally::of_reply_parts(&parts(
                "@/a",
                PartsBody::Put(b"answer"),
                Some(&b"att"[..])
            ))),
            (
                Priority::DataHigh,
                NetworkStatsClass::net(
                    MessageLabel::Reply,
                    StatMessage::Reply,
                    StatSpace::Admin,
                    "answer".len() + attachment
                )
            )
        );
    }

    /// The answer to a member's interest, handed as its owned record, is counted as the item it
    /// copies to: a control message of the declare kind. Turned red by a lent record whose tally
    /// is not its item's.
    #[cfg(feature = "liveliness-token")]
    #[test]
    fn a_declare_reply_handed_as_its_record_is_counted_as_its_item() {
        let declare = crate::declare_build::build_declare_final_reply(7);
        let lent = MulticastTxReply::DeclareReply(&declare);
        assert_eq!(
            read(&lent.tally()),
            read(&MulticastTxTally::of(&lent.to_item()))
        );
        assert_eq!(
            *lent.tally().class(),
            NetworkStatsClass::control(MessageLabel::Declare)
        );
    }
}

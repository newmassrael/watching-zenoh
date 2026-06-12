// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use alloc::vec::Vec;

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
#[derive(Debug)]
pub enum MulticastTxItem {
    /// A pub/sub Push (`z_put` / `z_del` over multicast). Framed via the
    /// [`encode_frame_with_push`](crate::frame_encode::encode_frame_with_push)
    /// SSOT with a freshly minted channel SN.
    #[cfg(feature = "codec-push")]
    Push {
        /// The built Push network message
        /// ([`build_push_literal`](crate::push_build::build_push_literal) and
        /// friends).
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
        response: wz_codecs::response::ResponseOwned,
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
        declare: wz_codecs::declare::DeclareOwned,
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

/// Mint the channel SN for `item`, encode its network message into a
/// `T_MID_FRAME` via the matching `encode_frame_with_*` SSOT, and re-frame it
/// into a `T_MID_FRAGMENT` chain when the frame exceeds the group batch budget
/// ([`batch_size`](crate::multicast_params::MulticastParams::batch_size)). The
/// TX twin of
/// [`dispatch_multicast_inbound`](crate::multicast_rx::dispatch_multicast_inbound);
/// the caller multicasts the returned [`MulticastTxFrames::datagrams`] in order
/// on its own driver.
///
/// `Push` mints on the channel its `reliable` flag selects; the queryable
/// `Response` / `ResponseFinal` and the liveliness `DeclareReply` are pinned
/// reliable (a dropped reply / terminal hangs the peer's pending get, so they
/// ride the reliable SN ring + R flag — zenoh-pico parity). Every variant
/// routes through the one
/// [`multicast_frame_or_fragments`](crate::frame_encode::multicast_frame_or_fragments)
/// egress path; a `ResponseFinal` is a single tiny VLE rid that never reaches
/// the budget, so that call returns its one frame with no follow-on mint
/// (byte-identical to a dedicated single send).
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
    tx_sn: &mut crate::sn::TxSn,
    params: &crate::multicast_params::MulticastParams,
) -> MulticastTxFrames {
    match item {
        // TxData: mint the channel SN, wrap in a T_MID_FRAME (frame_encode
        // SSOT), and let multicast_frame_or_fragments re-frame an oversize
        // frame into a T_MID_FRAGMENT chain riding the same minted SN + the
        // follow-on mints (R311ko, zenoh-pico common-TX parity). A dropped
        // datagram leaves an SN gap inside receivers' half-window — though a
        // hole in a fragment chain aborts that chain at every receiver, as on
        // pico — so the loop's send is best-effort like the JOIN beacon.
        #[cfg(feature = "codec-push")]
        MulticastTxItem::Push { push, reliable } => {
            let frame_sn = tx_sn.mint(reliable);
            let dgram = crate::frame_encode::encode_frame_with_push(frame_sn, push, reliable);
            let datagrams = crate::frame_encode::multicast_frame_or_fragments(
                dgram,
                frame_sn,
                reliable,
                params.batch_size as usize,
                tx_sn,
            );
            MulticastTxFrames {
                datagrams,
                reliable,
            }
        }
        // R311lq — queryable reply egress. Reliable like a reliable-ring put
        // (zenoh-pico replies via the same `_z_send_n_msg` multicast TX with
        // `Z_RELIABILITY_RELIABLE`); a large reply re-frames as a fragment
        // chain exactly like an oversize Push.
        #[cfg(feature = "codec-response")]
        MulticastTxItem::Response { response } => {
            let frame_sn = tx_sn.mint(/* reliable = */ true);
            let dgram = crate::frame_encode::encode_frame_with_response(
                frame_sn, response, /* reliable = */ true,
            );
            let datagrams = crate::frame_encode::multicast_frame_or_fragments(
                dgram,
                frame_sn,
                true,
                params.batch_size as usize,
                tx_sn,
            );
            MulticastTxFrames {
                datagrams,
                reliable: true,
            }
        }
        // R311lq — the terminal of a multicast reply chain. Always reliable and
        // always tiny (a single VLE rid), so it never reaches the fragment
        // budget: one minted reliable-ring SN, one frame. Mirrors the unicast
        // `send_response_final` (reliability pinned).
        #[cfg(feature = "codec-response-final")]
        MulticastTxItem::ResponseFinal { request_id } => {
            let frame_sn = tx_sn.mint(/* reliable = */ true);
            let dgram = crate::frame_encode::encode_frame_with_response_final(
                frame_sn,
                crate::response_final_build::build_response_final(request_id),
                /* reliable = */ true,
            );
            // Uniform egress: a ResponseFinal is a single tiny VLE rid that never
            // reaches the budget, so multicast_frame_or_fragments returns the one
            // frame with no follow-on mint (byte-identical to a single send) -
            // one path for all four variants rather than a special case.
            let datagrams = crate::frame_encode::multicast_frame_or_fragments(
                dgram,
                frame_sn,
                true,
                params.batch_size as usize,
                tx_sn,
            );
            MulticastTxFrames {
                datagrams,
                reliable: true,
            }
        }
        // R311lr — declarer-side liveliness interest-response egress. Reliable —
        // zenoh-pico's `_z_send_declare` rides `_z_send_n_msg` with
        // `Z_RELIABILITY_RELIABLE` (src/net/primitives.c:52); a large held-token
        // keyexpr re-frames as a fragment chain exactly like an oversize Push.
        #[cfg(feature = "liveliness-token")]
        MulticastTxItem::DeclareReply { declare } => {
            let frame_sn = tx_sn.mint(/* reliable = */ true);
            let dgram = crate::frame_encode::encode_frame_with_declare(
                frame_sn, declare, /* reliable = */ true,
            );
            let datagrams = crate::frame_encode::multicast_frame_or_fragments(
                dgram,
                frame_sn,
                true,
                params.batch_size as usize,
                tx_sn,
            );
            MulticastTxFrames {
                datagrams,
                reliable: true,
            }
        }
    }
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
        push: crate::push_build::build_push_literal(keyexpr_suffix, payload)?,
        reliable: true,
    })
}

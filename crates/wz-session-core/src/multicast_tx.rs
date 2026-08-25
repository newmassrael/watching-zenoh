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

// Only the boxed variants (Push / Response / DeclareReply) name Box; a build
// with only the unboxed ResponseFinal (or no data codec) must not import it.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "liveliness-token"
))]
use alloc::boxed::Box;
use alloc::vec::Vec;

// R311y227 — the per-priority multicast conduit send-side band type. Gated on the
// data codec that carries a band (Push); the reply-plane variants are DEFAULT.
#[cfg(feature = "codec-push")]
use crate::qos::Priority;

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
/// R311y227 — the multicast send-side band clamp: the app / routing priority
/// when the group negotiated `is_qos` under `transport-qos`, else
/// [`Priority::DEFAULT`]. A build WITHOUT `transport-qos` has no per-priority
/// conduit, so the band is always elided to DEFAULT — no non-DEFAULT frame can
/// ride (the pico-faithful 2-channel default), and a non-qos / pico receiver
/// never decodes an "Unknown priority" frame.
#[cfg(feature = "codec-push")]
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
#[cfg(feature = "codec-push")]
fn frame_ext_qos(priority: Priority) -> Option<Priority> {
    (priority != Priority::DEFAULT).then_some(priority)
}

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
    match item {
        // TxData: mint the channel SN, wrap in a T_MID_FRAME (frame_encode
        // SSOT), and let multicast_frame_or_fragments re-frame an oversize
        // frame into a T_MID_FRAGMENT chain riding the same minted SN + the
        // follow-on mints (R311ko, zenoh-pico common-TX parity). A dropped
        // datagram leaves an SN gap inside receivers' half-window — though a
        // hole in a fragment chain aborts that chain at every receiver, as on
        // pico — so the loop's send is best-effort like the JOIN beacon.
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
            let eff = effective_mcast_priority(priority, params.is_qos);
            let ext_qos = frame_ext_qos(eff);
            let frame_sn = tx_sn.mint(eff, reliable);
            let dgram =
                crate::frame_encode::encode_frame_with_push_qos(frame_sn, *push, reliable, ext_qos);
            let datagrams = crate::frame_encode::multicast_frame_or_fragments(
                dgram,
                frame_sn,
                reliable,
                params.batch_size as usize,
                tx_sn,
                ext_qos,
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
            let frame_sn = tx_sn.mint(crate::qos::Priority::DEFAULT, /* reliable = */ true);
            let dgram = crate::frame_encode::encode_frame_with_response(
                frame_sn, *response, /* reliable = */ true,
            );
            let datagrams = crate::frame_encode::multicast_frame_or_fragments(
                dgram,
                frame_sn,
                true,
                params.batch_size as usize,
                tx_sn,
                // Control-plane reply frames (Response / ResponseFinal /
                // DeclareReply) are DEFAULT-band (zenoh treats reply priority as a
                // separate concern); no frame ext_qos, no per-priority conduit.
                None,
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
            let frame_sn = tx_sn.mint(crate::qos::Priority::DEFAULT, /* reliable = */ true);
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
                // Control-plane reply frames (Response / ResponseFinal /
                // DeclareReply) are DEFAULT-band (zenoh treats reply priority as a
                // separate concern); no frame ext_qos, no per-priority conduit.
                None,
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
            let frame_sn = tx_sn.mint(crate::qos::Priority::DEFAULT, /* reliable = */ true);
            let dgram = crate::frame_encode::encode_frame_with_declare(
                frame_sn, *declare, /* reliable = */ true,
            );
            let datagrams = crate::frame_encode::multicast_frame_or_fragments(
                dgram,
                frame_sn,
                true,
                params.batch_size as usize,
                tx_sn,
                // Control-plane reply frames (Response / ResponseFinal /
                // DeclareReply) are DEFAULT-band (zenoh treats reply priority as a
                // separate concern); no frame ext_qos, no per-priority conduit.
                None,
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

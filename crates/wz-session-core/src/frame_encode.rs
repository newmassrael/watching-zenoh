// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Outbound `T_MID_FRAME` envelope encoders.
//!
//! `encode_frame_envelope` composes the parent-flags byte + `VLE(sn)` +
//! a sink-encoded network-message payload into one growable `Vec`; the
//! `encode_frame_with_*` family are the per-network-message wrappers
//! (Push / Declare / Request / Response / ResponseFinal / Interest) the
//! `SessionLinkActions` action layer emits.
//!
//! Hoisted from `wz-runtime-tokio::session_glue` so both runtime profiles
//! share one outbound encode SSOT — the MCU `#![no_std]` profile cannot
//! depend on the tokio crate. Pure (no runtime / no tokio); owned `Vec`
//! output makes it the alloc-profile encoder (`alloc`-gated at the
//! `lib.rs` module declaration).

use alloc::vec::Vec;

use sce_forge_runtime::codec::{CodecError, SceSink, VecSink};
use wz_codecs::wire_const;

use crate::qos::Priority;

#[cfg(feature = "codec-declare")]
use wz_codecs::declare::{Declare, DeclareOwned};
use wz_codecs::interest::{Interest, InterestOwned};
#[cfg(all(feature = "codec-linkstate", feature = "codec-push"))]
use wz_codecs::oam::OamOwned;
#[cfg(feature = "codec-push")]
use wz_codecs::push::{Push, PushOwned};
#[cfg(feature = "codec-request")]
use wz_codecs::request::{Request, RequestOwned};
#[cfg(feature = "codec-response")]
use wz_codecs::response::{Response, ResponseOwned};
#[cfg(feature = "codec-response-final")]
use wz_codecs::response_final::{ResponseFinal, ResponseFinalOwned};

/// R311jq — the FRAME parent-flags byte for a channel: `FLAG_T_FRAME_R`
/// (0x20) when reliable, 0 otherwise, matching zenoh-pico's
/// `_z_frame_encode` (`src/protocol/codec/transport.c:380`). `FLAG_T_Z`
/// (0x80, Frame-level transport extensions) is never set — the MVP data
/// path has no Frame-level ext chain (see `ExtChainRole` for the
/// handshake chains).
pub(crate) fn frame_flags(reliable: bool) -> u8 {
    if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    }
}

/// R311y215 — the `ext_qos` transport-extension header byte written after
/// `VLE(sn)` on a QoS Frame / Fragment: ext-id `0x1`, encoding `z64` (`0b01 <<
/// 5` = `0x20`), MANDATORY (`M`, `0x10`) → `0x31`. zenoh
/// `frame::ext::QoS = fragment::ext::QoS = zextz64!(0x1, true)`
/// (`commons/zenoh-protocol/src/transport/{frame,fragment}.rs`); the ext-header
/// bit layout is `id[0:3] | M[4] | enc[5:6] | Z[7]`
/// (`commons/zenoh-protocol/src/common/extension.rs:60-68`), matching the wz
/// `ExtEntry` codec. The z64 body is a single `VLE(priority)` (the transport
/// `QoSType` packs the priority in the low 3 bits, the rest reserved —
/// congestion/express are network-QoS, not transport;
/// `transport/mod.rs:268-286`). Mandatory means a peer that does not understand
/// QoS must reject the frame rather than skip the ext — but a peer only sees
/// this ext when it negotiated `is_qos` in the first place, so the M bit is a
/// belt-and-braces faithfulness detail (RANK1) rather than a live divergence.
#[cfg(feature = "transport-qos")]
const QOS_EXT_HEADER: u8 = 0x31;

/// R311y215 — the on-wire byte width of one `ext_qos` extension: the `0x31`
/// header + a single-byte `VLE(priority)` (priority is `0..=7`, always `< 0x80`,
/// so the VLE is one byte). The fragment chunk-budget subtracts this on every
/// fragment when QoS rides the chain (see [`fragment_chunk_size`]).
#[cfg(feature = "transport-fragmentation")]
const QOS_EXT_WIRE_BYTES: usize = 2;

/// R311y215 — append one `ext_qos` extension (`[header][VLE(priority)]`) to
/// `buf`. `chained` sets the ext-chain continuation `Z` bit (`0x80`) so a
/// further extension (the Fragment `FRAGMENT_FIRST` marker, id `0x2`) can follow
/// — zenoh writes the exts in id-ascending order (`0x1` QoS, then `0x2` First),
/// each carrying the continuation bit while another follows
/// (`zenoh-codec/src/transport/fragment.rs` `write`). The z64 body reuses the
/// codec's `write_vle_u64` primitive rather than a hand-rolled VLE.
#[cfg(feature = "transport-qos")]
fn write_qos_ext(buf: &mut Vec<u8>, priority: Priority, chained: bool) {
    let header = if chained {
        QOS_EXT_HEADER | wire_const::FLAG_T_Z
    } else {
        QOS_EXT_HEADER
    };
    buf.push(header);
    let mut sink = VecSink::new(buf);
    sink.write_vle_u64(priority.wire_byte() as u64)
        .expect("VecSink is infallible");
}

/// R311jq — write the FRAME prefix (header byte + `VLE(sn)`) into `buf`.
/// The single home of the prefix wire format, shared by the
/// immediate-path [`encode_frame_envelope`] and the batching open-frame
/// writer in `SessionLinkActions`.
///
/// The `VLE(sn)` loop is bit-identical to `Frame::encode`'s sn block
/// — it IS the wire format (zenoh-pico VLE base-128 encoding per
/// `vendor/zenoh-pico/src/protocol/codec/core.c`), not consumer-tunable
/// logic.
///
/// R311y215 — `ext_qos` carries the Frame's QoS priority (`Some` iff a QoS
/// session sends a non-DEFAULT priority; see
/// [`crate::session_actions::SessionLinkActions::dispatch_network_message`]).
/// When present the header gains `FLAG_T_Z` and a single z64 ext_qos
/// (`[0x31][VLE(priority)]`, [`write_qos_ext`]) is written between `VLE(sn)` and
/// the payload — zenoh `frame::ext::QoS`, written only when `!= DEFAULT`
/// (`zenoh-codec/src/transport/frame.rs`). A `None` (DEFAULT / non-QoS) Frame is
/// byte-identical to a pre-QoS Frame. The Frame carries only the QoS ext (no
/// First/Drop markers — those are Fragment-only), so the ext is never chained.
pub(crate) fn begin_frame(buf: &mut Vec<u8>, sn: u64, parent_flags: u8, ext_qos: Option<Priority>) {
    // The QoS ext (when present) sets the Frame-level ext-chain Z flag.
    #[cfg(feature = "transport-qos")]
    let z = if ext_qos.is_some() {
        wire_const::FLAG_T_Z
    } else {
        0u8
    };
    #[cfg(not(feature = "transport-qos"))]
    let z = {
        let _ = ext_qos;
        0u8
    };
    buf.push(parent_flags | z | wire_const::T_MID_FRAME);
    {
        let mut sink = VecSink::new(buf);
        let mut vle = sn;
        while vle >= 0x80 {
            sink.write_u8((vle as u8 & 0x7F) | 0x80)
                .expect("VecSink is infallible");
            vle >>= 7;
        }
        sink.write_u8(vle as u8).expect("VecSink is infallible");
    }
    #[cfg(feature = "transport-qos")]
    if let Some(priority) = ext_qos {
        // Frame's sole ext → never chained (Z clear on the ext header).
        write_qos_ext(buf, priority, false);
    }
}

/// R311jq — derive the link-driver [`Reliability`] of an already-encoded
/// outbound `T_MID_FRAME` from its header's R flag. Two callers: (1) the
/// batch flush paths re-emit a frame that was opened by an earlier
/// message, so the channel must come from the frame bytes, not from the
/// currently-dispatched message; (2) R311y222 — the batch reopen check
/// reads the OPEN frame's R flag through this to detect a reliability
/// change and flush+reopen, so wz keeps each batch frame homogeneous in
/// (priority, reliability). This is where wz DIVERGES from vendored
/// zenoh-pico, which appends mixed-reliability messages into whatever
/// frame is open (`tx.c _z_transport_tx_send_n_msg_inner` mints the header
/// only when the buffer is empty, then blind-appends); wz instead follows
/// zenoh's per-(priority, reliability) frame boundary.
///
/// cfg adds `session-unicast`: every consumer (the batch flush emits)
/// lives in `session_actions`, which is gated `all(alloc,
/// session-unicast)` — a batching-without-session subset must not carry
/// the dead symbol (`-D warnings` C1h lanes).
#[cfg(all(feature = "transport-batching", feature = "session-unicast"))]
pub(crate) fn frame_wire_reliability(bytes: &[u8]) -> crate::reliability::Reliability {
    let reliable = bytes
        .first()
        .is_some_and(|h| h & wire_const::FLAG_T_FRAME_R != 0);
    if reliable {
        crate::reliability::Reliability::Reliable
    } else {
        crate::reliability::Reliability::BestEffort
    }
}

/// R121h-perf-bump-3 — single-allocation transport-envelope encode.
/// Composes the parent-flags byte, `VLE(sn)`, and a sink-encoded
/// payload into one growable `Vec`, eliminating the prior
/// `payload.encode_to_vec()` + `Frame.encode_to_vec()` +
/// `wire.extend_from_slice(&body_bytes)` chain (3 allocations per
/// hot-path emit). For typical 1–2 KB payloads the reserved capacity
/// is also dramatically smaller than the 64 KB `Frame::MAX_ENCODED_BYTES`
/// ceiling, since the inner codec's worst-case bound is used directly.
/// R311jq lifts the prefix write into [`begin_frame`] so the batching
/// open-frame writer shares the same bytes-producing code.
pub(crate) fn encode_frame_envelope<P>(
    sn: u64,
    parent_flags: u8,
    worst_case_payload: usize,
    ext_qos: Option<Priority>,
    payload_encode: P,
) -> Vec<u8>
where
    P: FnOnce(&mut VecSink<'_>) -> Result<(), CodecError>,
{
    // +2 for a possible ext_qos ([0x31][VLE(priority)]); harmless slack when absent.
    let mut wire = Vec::with_capacity(1 + 10 + 2 + worst_case_payload);
    begin_frame(&mut wire, sn, parent_flags, ext_qos);
    {
        let mut sink = VecSink::new(&mut wire);
        payload_encode(&mut sink).expect("VecSink is infallible");
    }
    wire
}

/// R311jq — per-type network-message body encoder: the single home of
/// the `try_as_borrowed().encode(sink)` projection, shared by the
/// immediate-path `encode_frame_with_*` reference wrapper and the
/// batching-path direct-into-buffer append in `SessionLinkActions`
/// (`Fn`, not `FnOnce` — the batch-overflow retry encodes twice).
#[cfg(feature = "codec-push")]
pub(crate) fn push_body(
    push: &PushOwned,
) -> impl Fn(&mut VecSink<'_>) -> Result<(), CodecError> + '_ {
    move |sink| {
        push.try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    }
}

/// The `OAM_LINKSTATE` body encoder — the linkstate-peer routing TX path
/// (c3d) floods a self-built OAM carrier through the same
/// `dispatch_network_message` chokepoint as the data-plane senders. Same
/// `try_as_borrowed().encode(sink)` projection as [`push_body`]. Co-gated on
/// `codec-push` (the send path it feeds), so an encode-only `codec-linkstate`
/// build does not compile this orphaned.
#[cfg(all(feature = "codec-linkstate", feature = "codec-push"))]
pub(crate) fn oam_body(oam: &OamOwned) -> impl Fn(&mut VecSink<'_>) -> Result<(), CodecError> + '_ {
    move |sink| {
        oam.try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    }
}

/// R311jq — per-type network-message body encoder: the single home of
/// the `try_as_borrowed().encode(sink)` projection, shared by the
/// immediate-path `encode_frame_with_*` reference wrapper and the
/// batching-path direct-into-buffer append in `SessionLinkActions`
/// (`Fn`, not `FnOnce` — the batch-overflow retry encodes twice).
#[cfg(feature = "codec-declare")]
pub(crate) fn declare_body(
    declare: &DeclareOwned,
) -> impl Fn(&mut VecSink<'_>) -> Result<(), CodecError> + '_ {
    move |sink| {
        declare
            .try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    }
}

/// R311jq — per-type network-message body encoder: the single home of
/// the `try_as_borrowed().encode(sink)` projection, shared by the
/// immediate-path `encode_frame_with_*` reference wrapper and the
/// batching-path direct-into-buffer append in `SessionLinkActions`
/// (`Fn`, not `FnOnce` — the batch-overflow retry encodes twice).
#[cfg(feature = "codec-request")]
pub(crate) fn request_body(
    request: &RequestOwned,
) -> impl Fn(&mut VecSink<'_>) -> Result<(), CodecError> + '_ {
    move |sink| {
        request
            .try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    }
}

/// R311jq — per-type network-message body encoder: the single home of
/// the `try_as_borrowed().encode(sink)` projection, shared by the
/// immediate-path `encode_frame_with_*` reference wrapper and the
/// batching-path direct-into-buffer append in `SessionLinkActions`
/// (`Fn`, not `FnOnce` — the batch-overflow retry encodes twice).
#[cfg(feature = "codec-response")]
pub(crate) fn response_body(
    response: &ResponseOwned,
) -> impl Fn(&mut VecSink<'_>) -> Result<(), CodecError> + '_ {
    move |sink| {
        response
            .try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    }
}

/// R311jq — per-type network-message body encoder: the single home of
/// the `try_as_borrowed().encode(sink)` projection, shared by the
/// immediate-path `encode_frame_with_*` reference wrapper and the
/// batching-path direct-into-buffer append in `SessionLinkActions`
/// (`Fn`, not `FnOnce` — the batch-overflow retry encodes twice).
#[cfg(feature = "codec-response-final")]
pub(crate) fn response_final_body(
    response_final: &ResponseFinalOwned,
) -> impl Fn(&mut VecSink<'_>) -> Result<(), CodecError> + '_ {
    move |sink| {
        response_final
            .try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    }
}

/// R311jq — per-type network-message body encoder: the single home of
/// the `try_as_borrowed().encode(sink)` projection, shared by the
/// immediate-path `encode_frame_with_*` reference wrapper and the
/// batching-path direct-into-buffer append in `SessionLinkActions`
/// (`Fn`, not `FnOnce` — the batch-overflow retry encodes twice).
pub(crate) fn interest_body(
    interest: &InterestOwned,
) -> impl Fn(&mut VecSink<'_>) -> Result<(), CodecError> + '_ {
    move |sink| {
        interest
            .try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    }
}

/// R121j-3 — build the wire bytes for a `Frame` transport-message
/// carrying a single `Response` network-message in its payload.
/// Mirror of the other `encode_frame_with_*` helpers (PUSH /
/// DECLARE / REQUEST / RESPONSE_FINAL).
///
/// Reply data delivery is on the reliable channel by default — a
/// dropped Reply leaves the requester's `z_get` waiting for a
/// reply that never arrives, then for the matching
/// `ResponseFinal` that the queryable never re-emits (because from
/// its perspective the reply was sent). The default `reliable=true`
/// is the production-safe choice; callers passing `false` accept
/// the consequence.
#[cfg(feature = "codec-response")]
pub fn encode_frame_with_response(sn: u64, response: ResponseOwned, reliable: bool) -> Vec<u8> {
    encode_frame_envelope(
        sn,
        frame_flags(reliable),
        Response::MAX_ENCODED_BYTES,
        None,
        response_body(&response),
    )
}

/// R121j-2 — build the wire bytes for a `Frame` transport-message
/// carrying a single `ResponseFinal` network-message in its payload.
/// Mirror of the other `encode_frame_with_*` helpers (PUSH /
/// DECLARE / REQUEST).
///
/// ResponseFinal is unconditionally reliable in zenoh-pico's model:
/// dropping a ResponseFinal would leave the requesting peer's
/// `z_get` future hung waiting for sequence termination. The default
/// `reliable=true` is the production-safe choice; callers passing
/// `false` accept the consequence (typically only fuzz / negative
/// tests).
#[cfg(feature = "codec-response-final")]
pub fn encode_frame_with_response_final(
    sn: u64,
    response_final: ResponseFinalOwned,
    reliable: bool,
) -> Vec<u8> {
    encode_frame_envelope(
        sn,
        frame_flags(reliable),
        ResponseFinal::MAX_ENCODED_BYTES,
        None,
        response_final_body(&response_final),
    )
}

/// R121j-1 — build the wire bytes for a `Frame` transport-message
/// carrying a single `Request` network-message in its payload. Mirror
/// of [`encode_frame_with_push`] / [`encode_frame_with_declare`] for
/// the REQUEST outbound path.
///
/// Like the DECLARE outbound path, Request(Query) goes on the
/// reliable channel by default — the peer's responder side needs to
/// see the Query to dispatch into its queryable callback; an
/// unreliable Query could silently drop and leave the local
/// `z_get` future hung without a Response or ResponseFinal. Callers
/// that pass `reliable=false` accept that risk explicitly.
#[cfg(feature = "codec-request")]
pub fn encode_frame_with_request(sn: u64, request: RequestOwned, reliable: bool) -> Vec<u8> {
    encode_frame_envelope(
        sn,
        frame_flags(reliable),
        Request::MAX_ENCODED_BYTES,
        None,
        request_body(&request),
    )
}

/// R121g — build the wire bytes for a `Frame` transport-message
/// carrying a single `Declare` network-message in its payload.
/// Mirror of [`encode_frame_with_push`] for the DECLARE outbound
/// path.
///
/// `parent_flags` carries `FLAG_T_FRAME_R (0x20)` when `reliable`,
/// matching zenoh-pico's `_z_frame_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/transport.c:380`.
/// DECLARE outbound is always reliable in the AP MVP path — the
/// session-FSM reliable-channel SN window orders DECLARE before
/// any dependent aliased Push, so the peer's keyexpr table is
/// populated before the first resolving Push arrives. Callers
/// passing `reliable=false` accept that the DECLARE may arrive
/// after a referencing Push and the peer's resolver will reject
/// the unknown id — useful only for fuzz / negative tests.
#[cfg(feature = "codec-declare")]
pub fn encode_frame_with_declare(sn: u64, declare: DeclareOwned, reliable: bool) -> Vec<u8> {
    encode_frame_envelope(
        sn,
        frame_flags(reliable),
        Declare::MAX_ENCODED_BYTES,
        None,
        declare_body(&declare),
    )
}

/// R279 — build the wire bytes for a `Frame` transport-message
/// carrying a single `Interest` network-message in its payload.
/// Mirror of [`encode_frame_with_declare`] for the INTEREST outbound
/// path (declarations-discovery / liveliness-subscriber registration).
///
/// `parent_flags` carries `FLAG_T_FRAME_R (0x20)` when `reliable`,
/// matching zenoh-pico's `_z_frame_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/transport.c:380`. INTEREST
/// outbound is always reliable in the wz path: the peer's
/// `_z_interest_process_*` runs against an ordered stream of
/// DeclToken / UndeclToken / InterestFinal records on the reliable
/// channel, and the SN-window orders the Interest before any peer
/// reply just as the DECLARE path orders DeclSubscriber before any
/// resolving Push. Callers passing `reliable=false` accept that the
/// Interest may arrive after a peer-side state change and the peer's
/// resolver may serve a stale history snapshot — useful only for
/// fuzz / negative tests.
pub fn encode_frame_with_interest(sn: u64, interest: InterestOwned, reliable: bool) -> Vec<u8> {
    encode_frame_envelope(
        sn,
        frame_flags(reliable),
        Interest::MAX_ENCODED_BYTES,
        None,
        interest_body(&interest),
    )
}

/// R121e — build the wire bytes for a `Frame` transport-message
/// (T_MID_FRAME) carrying a single `Push` network-message in its
/// payload.
///
/// Wire shape (composes the transport-envelope header byte that
/// lives outside the body codec's scope with `Frame.encode_to_vec()`'s
/// `VLE(sn) + payload` body):
///
/// ```text
///   [parent_flags | T_MID_FRAME (0x05)]
///     VLE(sn) | push.encode_bytes
/// ```
///
/// `parent_flags` carries `FLAG_T_FRAME_R` (0x20) when
/// `reliable`, matching zenoh-pico's `_z_frame_encode` per
/// `vendor/zenoh-pico/src/protocol/codec/transport.c:380`.
/// `FLAG_T_Z` (0x80) — Frame-level transport extensions — is not
/// set: the MVP pub/sub path has no use for transport-level
/// Frame extensions and the wireless QoS / Auth ext chains live
/// on the InitSyn / InitAck negotiation paths (see
/// `ExtChainRole`).
///
/// The `Frame { sn, payload }.encode_to_vec()` body is verified
/// byte-identical to zenoh-pico's `_z_frame_encode` by
/// `crates/wz-integration-tests/tests/layer3_frame.rs`. This
/// helper composes only the one transport header byte that
/// `Frame::encode` does not emit.
#[cfg(feature = "codec-push")]
pub fn encode_frame_with_push(sn: u64, push: PushOwned, reliable: bool) -> Vec<u8> {
    // DEFAULT anchor: no Frame ext_qos, byte-identical to every pre-QoS caller
    // (the ~10 existing call sites + all layer3 byte-equiv tests). The multicast
    // per-priority TX emit uses the `_qos` twin below (R311y227); keeping this
    // ext_qos-free preserves the anchor exactly (the y226 build_push_literal
    // idiom — the DEFAULT fast path stays the byte-verified reference).
    encode_frame_with_push_qos(sn, push, reliable, None)
}

/// R311y227 — the QoS-carrying twin of [`encode_frame_with_push`]: writes the
/// Frame `ext_qos` (id 0x1, header 0x31, low-3-bit priority — [`begin_frame`] /
/// [`write_qos_ext`]) when `ext_qos` is `Some(non-DEFAULT priority)`, else
/// byte-identical to the anchor. The multicast per-priority TX emit
/// ([`crate::multicast_tx::multicast_tx_emit`]) passes the clamped conduit
/// priority; `None` (DEFAULT / non-qos group) carries no ext, so a pico /
/// non-qos receiver never decodes an "Unknown priority" frame (zenoh
/// `io/zenoh-transport/src/multicast/rx.rs` bails on a non-DEFAULT frame at a
/// non-qos peer). The unicast TX writes the same ext through its batch writer
/// ([`crate::session_actions`]), not this helper.
#[cfg(feature = "codec-push")]
pub fn encode_frame_with_push_qos(
    sn: u64,
    push: PushOwned,
    reliable: bool,
    ext_qos: Option<Priority>,
) -> Vec<u8> {
    encode_frame_envelope(
        sn,
        frame_flags(reliable),
        Push::MAX_ENCODED_BYTES,
        ext_qos,
        push_body(&push),
    )
}

// ── transport fragmentation (transport-fragmentation gated) ───────────────
// zenoh-pico `_z_transport_tx_send_fragment` parity
// (`src/transport/common/tx.c`): when a serialized network-message body does
// not fit the link MTU, split it into `T_MID_FRAGMENT` chunks — M (more) set
// on every chunk but the last, R (reliable) per the channel — each consuming
// one outbound frame SN. The fragment wire body is `VLE(sn) + tail payload`
// (the R/M/Z flags live in the 1-byte header, not the body); it is inlined
// here for the same reason `encode_frame_envelope` inlines the FRAME
// `VLE(sn)` — it IS the wire format, and the decode side (`inbound.rs`
// `T_MID_FRAGMENT` arm) inlines the symmetric `VLE(sn) + tail` parse. The
// reassembly dispatcher requires the chunk SNs to be consecutive (it aborts a
// chain on `fragment.ooo`), so the caller draws the SN block atomically.

/// Base-128 VLE byte width of `sn` — the offset math the fragmentation
/// body-slice uses to locate a FRAME's network-message tail behind the
/// 1-byte header + `VLE(sn)` prefix that [`encode_frame_envelope`] wrote.
/// Mirrors the encoder's emit loop exactly; it IS the wire format, not
/// consumer-tunable logic.
///
/// cfg = fragmentation only (R311ko): the codec-agnostic
/// [`multicast_frame_or_fragments`] body-slice joined the unicast
/// `emit_frame_or_fragments` as a consumer, so the former wire-emit
/// codec union (R311jq) no longer bounds where the symbol is live —
/// any fragmentation build slices.
#[cfg(feature = "transport-fragmentation")]
fn vle_width(sn: u64) -> usize {
    let (mut width, mut v) = (1usize, sn);
    while v >= 0x80 {
        v >>= 7;
        width += 1;
    }
    width
}

/// R311kq — the network-message body of an already-encoded outbound
/// `T_MID_FRAME`: the tail behind the 1-byte header + `VLE(sn)` prefix
/// [`encode_frame_envelope`] wrote. The single home of the FRAME-prefix
/// offset contract — both fragmentation re-framers (the unicast
/// `emit_frame_or_fragments` and [`multicast_frame_or_fragments`]) slice
/// through this instead of each re-deriving `1 + vle_width(sn)`.
///
/// R311y215 — a QoS Frame additionally carries a 2-byte `ext_qos`
/// ([`QOS_EXT_WIRE_BYTES`], `[0x31][VLE(priority)]`) between `VLE(sn)` and the
/// NetworkMessage batch. When re-fragmenting such a frame the ext_qos MUST be
/// stripped here too — each fragment re-frames its OWN ext_qos, so the fragment
/// payloads carry ONLY the batch; leaving the frame's ext_qos in `body` would
/// prepend a stray `[0x31][priority]` to the reassembled batch and break the
/// peer's `parse_frame_payload` (`0x31 & 0x1F` is not a valid network MID). The
/// non-QoS / DEFAULT path passes `None` and slices exactly as before.
#[cfg(feature = "transport-fragmentation")]
pub(crate) fn frame_wire_body(frame: &[u8], sn: u64, ext_qos: Option<Priority>) -> &[u8] {
    let mut off = 1 + vle_width(sn);
    if ext_qos.is_some() {
        off += QOS_EXT_WIRE_BYTES;
    }
    &frame[off..]
}

/// Conservative per-fragment header budget: 1 flags byte + the maximum u64
/// VLE width (10). Sizing chunks against the *maximum* SN width (rather than
/// each fragment's actual SN width) makes the fragment count computable
/// *before* the SN block is reserved, and guarantees every emitted fragment is
/// `<= mtu` whatever its SN. The few unused payload bytes per fragment are
/// negligible against a multi-KB body.
///
/// The FIRST fragment additionally carries the 1-byte [`FRAGMENT_FIRST_EXT_HEADER`]
/// after its `VLE(sn)`. It still fits `<= mtu`: the first-fragment wire is
/// `1(header) + vle_width(sn) + 1(ext) + (mtu - BUDGET)` = `mtu - 9 +
/// vle_width(sn)`, and a ring-masked SN's real `vle_width` is `<= 9` (a
/// 63-bit `seq_num_res` is the widest ring), so the ext rides the slack between
/// the reserved max VLE width (10) and the real width — no chunk resize needed.
#[cfg(feature = "transport-fragmentation")]
const FRAG_HEADER_BUDGET: usize = 1 + 10;

/// The `FRAGMENT_FIRST` transport extension header byte written after `VLE(sn)`
/// on the FIRST fragment of a chain: ext-id `0x02`, encoding `unit` (`0b00`,
/// no body), non-mandatory (M=0), sole ext (Z=0) → `0x02`. zenoh
/// `fragment::ext::First = zextunit!(0x2, false)`
/// (`commons/zenoh-protocol/src/transport/fragment.rs`); zenoh-pico
/// `_Z_MSG_EXT_ID_FRAGMENT_FIRST` (`include/zenoh-pico/protocol/ext.h`). A peer
/// that negotiated protocol patch >= 1 (which wz always advertises, see
/// [`crate::session_actions::default_init_patch_ext_entry`]) REQUIRES this
/// marker on the chain's first fragment and silently drops the whole chain
/// without it (zenoh-pico `src/transport/unicast/rx.c`, "First fragment
/// received without the start marker").
#[cfg(feature = "transport-fragmentation")]
const FRAGMENT_FIRST_EXT_HEADER: u8 = 0x02;

/// Per-fragment payload capacity at this `mtu`. Floored at 1 so a pathological
/// `mtu <= FRAG_HEADER_BUDGET` still terminates (one body byte per fragment)
/// rather than dividing by zero; production `mtu` is the negotiated batch size,
/// far above the header budget.
///
/// R311y215 — a `qos` chain carries an `ext_qos` ([`QOS_EXT_WIRE_BYTES`]) on
/// EVERY fragment, so the budget grows by that width; a non-QoS chain (every
/// build without `transport-qos`, and every DEFAULT-priority frame) keeps the
/// pre-QoS budget, so its chunking — and its byte layout — is unchanged.
#[cfg(feature = "transport-fragmentation")]
fn fragment_chunk_size(mtu: usize, qos: bool) -> usize {
    let budget = FRAG_HEADER_BUDGET + if qos { QOS_EXT_WIRE_BYTES } else { 0 };
    mtu.saturating_sub(budget).max(1)
}

/// Number of `T_MID_FRAGMENT` frames a `body_len`-byte network message splits
/// into at this `mtu`. The caller reserves exactly this many consecutive SNs
/// before calling [`fragment_body`].
#[cfg(feature = "transport-fragmentation")]
pub(crate) fn fragment_count(body_len: usize, mtu: usize, qos: bool) -> usize {
    let chunk = fragment_chunk_size(mtu, qos);
    // ceil(body_len / chunk), min 1 (an empty body still emits one final
    // fragment — though the oversize precondition means body is never empty).
    body_len.div_ceil(chunk).max(1)
}

/// Split a serialized network-message `body` into the `T_MID_FRAGMENT` wire
/// frames, SNs walking the ring of `sn_mask` from `base_sn & sn_mask` for
/// `N == fragment_count(body.len(), mtu)` steps ([`crate::sn::increment`],
/// zenoh-pico `_z_sn_increment` — R311kb closed the unmasked walk that
/// diverged at the ring seam). `base_sn` may be the raw reserved counter
/// value; this walk is the chain's single masking point. Every fragment but
/// the last carries the M (more) flag; R (reliable) is set per `reliable`.
/// zenoh-pico `_z_transport_tx_send_fragment_inner` parity.
///
/// R311y215 — `ext_qos` (`Some` iff a QoS session sends a non-DEFAULT priority)
/// is written on EVERY fragment (zenoh `fragment::ext::QoS`,
/// `zenoh-codec/src/transport/fragment.rs`): a continuation fragment that
/// decoded as DEFAULT would miss its per-(priority,reliability) reassembly
/// chain, so the priority must ride each chunk. The first fragment chains the
/// QoS ext ahead of the `FRAGMENT_FIRST` marker (id order `0x1` then `0x2`). A
/// `None` chain is byte-identical to the pre-QoS fragment wire.
#[cfg(feature = "transport-fragmentation")]
pub fn fragment_body(
    body: &[u8],
    reliable: bool,
    mtu: usize,
    base_sn: u64,
    sn_mask: u64,
    ext_qos: Option<Priority>,
) -> Vec<Vec<u8>> {
    // A QoS chain shrinks every chunk by the per-fragment ext_qos width; without
    // `transport-qos` the ext is never present, so the chunking is unchanged.
    #[cfg(feature = "transport-qos")]
    let qos = ext_qos.is_some();
    #[cfg(not(feature = "transport-qos"))]
    let qos = {
        let _ = ext_qos;
        false
    };
    let chunk = fragment_chunk_size(mtu, qos);
    let mut out = Vec::with_capacity(fragment_count(body.len(), mtu, qos));
    let mut off = 0usize;
    let mut sn = base_sn & sn_mask;
    loop {
        let end = core::cmp::min(off + chunk, body.len());
        let more = end < body.len();
        out.push(build_fragment_wire(
            sn,
            &body[off..end],
            reliable,
            more,
            off == 0,
            ext_qos,
        ));
        off = end;
        if !more {
            break;
        }
        sn = crate::sn::increment(sn_mask, sn);
    }
    out
}

/// Encode one `T_MID_FRAGMENT` wire frame: a `[flags | T_MID_FRAGMENT]`
/// transport-message header byte (R/M/Z ride the header) followed by the
/// `wz_codecs::fragment` codec body (`VLE(sn) + tail payload`). The body is
/// the byte-verified SSOT — `layer3_fragment.rs` checks `Fragment::encode`
/// against zenoh-pico `_z_fragment_encode`, and `inbound.rs` decodes the
/// symmetric shape — so production TX shares it rather than re-deriving the
/// VLE wire. Mirrors zenoh-pico, where `_z_transport_message_encode` writes the
/// header and the fragment codec writes the body.
///
/// `first` (the chain's leading fragment) sets the header `Z` bit and inserts
/// the [`FRAGMENT_FIRST_EXT_HEADER`] (`0x02`) ext byte between `VLE(sn)` and
/// the payload — the chain-start marker a protocol-patch >= 1 peer requires
/// (see [`FRAGMENT_FIRST_EXT_HEADER`]). Composed here rather than in the
/// fragment codec, symmetric with `inbound.rs`'s hand-rolled `T_MID_FRAGMENT`
/// Z-gated ext-chain decode (the codec stays a pure `VLE(sn) + tail` SSOT; the
/// transport-level R/M/Z flags + ext chain live at this frame-composer layer).
///
/// R311y215 — `ext_qos` (`Some` iff a QoS chain) prepends a z64 `ext_qos`
/// ([`write_qos_ext`]) ahead of any `FRAGMENT_FIRST` marker, in zenoh's
/// id-ascending order (`0x1` QoS, then `0x2` First;
/// `zenoh-codec/src/transport/fragment.rs`). The ext-chain `Z` header bit is set
/// whenever EITHER ext is present; the QoS ext carries the chain-continuation
/// bit iff the First marker follows it.
#[cfg(feature = "transport-fragmentation")]
fn build_fragment_wire(
    sn: u64,
    payload: &[u8],
    reliable: bool,
    more: bool,
    first: bool,
    ext_qos: Option<Priority>,
) -> Vec<u8> {
    let mut flags = 0u8;
    if reliable {
        flags |= wire_const::FLAG_T_FRAGMENT_R;
    }
    if more {
        flags |= wire_const::FLAG_T_FRAGMENT_M;
    }
    #[cfg(feature = "transport-qos")]
    let has_qos = ext_qos.is_some();
    #[cfg(not(feature = "transport-qos"))]
    let has_qos = {
        let _ = ext_qos;
        false
    };
    // Z: a Fragment ext chain (ext_qos and/or the FRAGMENT_FIRST marker) follows.
    let has_ext = first || has_qos;
    if has_ext {
        flags |= wire_const::FLAG_T_Z;
    }
    let qos_reserve = if has_qos { QOS_EXT_WIRE_BYTES } else { 0 };
    let mut wire =
        Vec::with_capacity(FRAG_HEADER_BUDGET + payload.len() + usize::from(first) + qos_reserve);
    wire.push(flags | wire_const::T_MID_FRAGMENT);
    if has_ext {
        // Wire body: VLE(sn) + [ext_qos] + [FRAGMENT_FIRST] + payload. The codec
        // writes VLE(sn) with an empty payload (raw tail, no length prefix —
        // `Fragment::encode` is `write_vle_u64 + write_bytes`) so the SN wire
        // form stays the byte-verified SSOT; the ext chain + the real payload are
        // appended after, in id-ascending order.
        {
            let mut sink = VecSink::new(&mut wire);
            wz_codecs::fragment::Fragment { sn, payload: &[] }
                .encode(&mut sink)
                .expect("VecSink is infallible");
        }
        #[cfg(feature = "transport-qos")]
        if let Some(priority) = ext_qos {
            // The QoS ext chains to the FRAGMENT_FIRST marker iff `first`.
            write_qos_ext(&mut wire, priority, first);
        }
        if first {
            wire.push(FRAGMENT_FIRST_EXT_HEADER);
        }
        wire.extend_from_slice(payload);
    } else {
        let mut sink = VecSink::new(&mut wire);
        wz_codecs::fragment::Fragment { sn, payload }
            .encode(&mut sink)
            .expect("VecSink is infallible");
    }
    wire
}

/// R311ko — terminal framing for one multicast outbound emission: the
/// already-encoded `T_MID_FRAME` passes through when it fits `mtu`
/// (the group batch budget, `MulticastParams::batch_size`), else its
/// network-message body — the tail after the 1-byte header + `VLE(sn)` —
/// re-frames as a `T_MID_FRAGMENT` chain (zenoh-pico
/// `_z_transport_tx_send_n_msg_inner` -> `_z_transport_tx_send_fragment`,
/// common/tx.c — multicast rides the same common TX path). The multicast
/// twin of `SessionLinkActions::emit_frame_or_fragments`, hosted here
/// (pure, driver-free) so the AP drive loop and a future MCU multicast
/// loop share one egress SSOT — the TX mirror of
/// [`crate::multicast_dispatch::ingest_multicast_fragment`].
///
/// SN policy (pico parity, `_z_transport_tx_send_fragment_inner`): the
/// oversize frame's already-minted `sn` IS the first fragment SN, and
/// each further fragment mints the channel's next — the drive loop owns
/// `tx_sn` exclusively, so the chain stays ring-consecutive by
/// construction and no SN is ever skipped. The unicast
/// `emit_frame_or_fragments` twin mirrors this SN policy (R311y206 made it
/// reuse the oversize frame's `sn` as the first fragment SN + reserve only the
/// `count - 1` follow-ons, closing the prior 1-SN gap). The follow-on mints
/// advance `tx_sn`, so the next JOIN beacon advertises the post-chain `next_*`.
///
/// Without `transport-fragmentation` the frame passes through whatever
/// its size (zenoh-pico "Sending the message required fragmentation
/// feature that is deactivated") — the signature stays stable so the
/// drive loop carries no cfg at the call site.
pub fn multicast_frame_or_fragments(
    frame: Vec<u8>,
    sn: u64,
    reliable: bool,
    mtu: usize,
    tx_sn: &mut crate::sn::MulticastTxConduits,
    ext_qos: Option<Priority>,
) -> Vec<Vec<u8>> {
    // R311y227 — a qos multicast frame carries its `ext_qos` (id 0x1) exactly as
    // the unicast per-priority path does: the fragment re-frame re-emits that ext
    // on EVERY fragment and slices the frame body PAST it ([`frame_wire_body`]),
    // and the follow-on SNs mint on the SAME priority conduit the head frame drew
    // (`ext_qos.unwrap_or(DEFAULT)`) so a fragment chain never splits across
    // conduits (the per-(priority,reliability) reassembly key stays intact). A
    // `None` chain (DEFAULT / non-qos group) is byte-identical to the pre-qos
    // re-frame — the pico-faithful 2-channel path, where `tx_sn` collapses to the
    // single conduit and `mint` ignores the priority.
    #[cfg(feature = "transport-fragmentation")]
    if frame.len() > mtu {
        let body = frame_wire_body(&frame, sn, ext_qos);
        // `fragment_count` / `fragment_body` size chunks against the per-fragment
        // ext_qos width iff a qos chain; `ext_qos.is_some()` is that flag, and it
        // is always false without `transport-qos` (the emit passes `None`).
        let qos = ext_qos.is_some();
        let count = fragment_count(body.len(), mtu, qos);
        let mint_priority = ext_qos.unwrap_or(Priority::DEFAULT);
        let mask = tx_sn.mask();
        for _ in 1..count {
            tx_sn.mint(mint_priority, reliable);
        }
        return fragment_body(body, reliable, mtu, sn, mask, ext_qos);
    }
    #[cfg(not(feature = "transport-fragmentation"))]
    let _ = (sn, reliable, mtu, tx_sn, ext_qos);
    alloc::vec![frame]
}

// Each frame test builds a payload via a sibling codec builder, so the
// whole module gates on the union of those codecs (the ungated
// encode_frame_with_interest path has its coverage in the layer3 interop
// tests, not here).
#[cfg(all(
    test,
    any(
        feature = "codec-push",
        feature = "codec-declare",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final"
    )
))]
mod tests {
    use super::*;
    #[cfg(feature = "codec-declare")]
    use crate::declare_build::build_declare_kexpr;
    // parse_inbound / InboundFrame / Push are named only by the
    // encode_frame_with_push round-trip test (codec-push).
    #[cfg(feature = "codec-push")]
    use crate::inbound::{parse_inbound, InboundFrame};
    #[cfg(feature = "codec-request")]
    use crate::request_build::build_request_query;
    #[cfg(feature = "codec-response")]
    use crate::response_build::build_response_reply_literal;
    #[cfg(feature = "codec-response-final")]
    use crate::response_final_build::build_response_final;
    #[cfg(feature = "codec-push")]
    use wz_codecs::push::Push;
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-declare",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final"
    ))]
    use wz_codecs_test_support::TestWire;

    /// `encode_frame_with_push` composes the transport-envelope
    /// header byte (T_MID_FRAME | parent_flags) with the
    /// `Frame.wire()` body (VLE(sn) + payload). With reliable=true
    /// the FLAG_T_FRAME_R bit appears in the header byte.
    #[cfg(feature = "codec-push")]
    #[test]
    fn encode_frame_with_push_emits_transport_header_plus_frame_body() {
        // Empty-payload Push at sn=0 keeps the assertion focused on
        // the transport-envelope header byte and the Frame body
        // shape. Push::default()'s wire bytes are independently
        // pinned by layer3_push.rs's byte-equiv test.
        let push = Push::default().try_into_owned().unwrap();
        let push_bytes = push.wire();

        // Reliable Frame at sn=0.
        let wire_reliable =
            encode_frame_with_push(0, Push::default().try_into_owned().unwrap(), true);
        assert_eq!(
            wire_reliable[0],
            wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME,
            "reliable Frame must set FLAG_T_FRAME_R (0x20) on the parent header byte"
        );
        // Body shape: VLE(sn=0) = single byte 0x00, followed by
        // Push.wire() bytes verbatim.
        assert_eq!(wire_reliable[1], 0x00, "Frame.sn=0 VLE width = 1 byte 0x00");
        assert_eq!(
            &wire_reliable[2..],
            push_bytes.as_slice(),
            "tail of Frame envelope must be the Push.wire() bytes byte-for-byte"
        );

        // Best-effort Frame: same shape minus FLAG_T_FRAME_R.
        let wire_best_effort =
            encode_frame_with_push(0, Push::default().try_into_owned().unwrap(), false);
        assert_eq!(
            wire_best_effort[0],
            wire_const::T_MID_FRAME,
            "best-effort Frame must NOT set FLAG_T_FRAME_R; only T_MID_FRAME in the header"
        );
    }

    /// `encode_frame_with_push` round-trips the sn VLE width
    /// boundaries (single-byte 0..=127, two-byte 128..=16383,
    /// etc.) so a downstream `parse_frame_payload` consumer can
    /// recover the original sn. The Frame.encode body's VLE writer
    /// is shared with layer3_frame.rs's byte-equiv coverage; this
    /// test pins the transport-envelope wrapper around it.
    #[cfg(feature = "codec-push")]
    #[test]
    fn encode_frame_with_push_carries_vle_sn_across_widths() {
        for sn in [0u64, 1, 127, 128, 16383, 16384, 1_000_000] {
            let wire = encode_frame_with_push(sn, Push::default().try_into_owned().unwrap(), true);
            // Round-trip through parse_inbound to recover the
            // sn — it carries us through both the transport-header
            // byte decode AND the Frame.sn VLE decode.
            let parsed = parse_inbound(&wire).expect("parse_inbound on round-tripped Frame");
            match parsed {
                InboundFrame::Frame {
                    sn: parsed_sn,
                    reliable,
                    ..
                } => {
                    assert_eq!(parsed_sn, sn, "sn must round-trip through encode+parse");
                    assert!(
                        reliable,
                        "reliable=true → FLAG_T_FRAME_R → InboundFrame.reliable=true"
                    );
                }
                // InboundFrame intentionally omits Debug derive
                // (sce-codegen wz-codecs structs only derive
                // Default, so a wrapping `#[derive(Debug)]` here
                // would not compile). Fall back to a variant-name
                // string for the panic.
                other => panic!(
                    "encode_frame_with_push must produce an InboundFrame::Frame; got {}",
                    match other {
                        #[cfg(feature = "codec-init-body")]
                        InboundFrame::Init { .. } => "Init",
                        #[cfg(feature = "codec-open-body")]
                        InboundFrame::Open { .. } => "Open",
                        #[cfg(feature = "codec-close")]
                        InboundFrame::Close { .. } => "Close",
                        #[cfg(feature = "codec-keep-alive")]
                        InboundFrame::KeepAlive { .. } => "KeepAlive",
                        #[cfg(feature = "reassembly")]
                        InboundFrame::Fragment { .. } => "Fragment",
                        InboundFrame::Unknown { .. } => "Unknown",
                        InboundFrame::Frame { .. } => unreachable!(),
                    }
                ),
            }
        }
    }

    /// R121g — `encode_frame_with_declare` produces the same
    /// `[parent_flags | T_MID_FRAME]` + `Frame.wire()` wrapping
    /// as `encode_frame_with_push`, with `Declare.wire()` as the
    /// inner payload bytes. Reliable / best-effort header flag
    /// behaviour mirrors the Push variant.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn encode_frame_with_declare_wraps_declare_in_frame_envelope() {
        let declare = build_declare_kexpr(7, "demo/test").unwrap();
        let declare_bytes = declare.wire();

        let wire_reliable =
            encode_frame_with_declare(0, build_declare_kexpr(7, "demo/test").unwrap(), true);
        assert_eq!(
            wire_reliable[0],
            wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME,
            "reliable Frame must set FLAG_T_FRAME_R on the parent header",
        );
        assert_eq!(wire_reliable[1], 0x00, "sn=0 VLE = single byte 0x00");
        assert_eq!(
            &wire_reliable[2..],
            declare_bytes.as_slice(),
            "Frame body tail must be Declare.wire() bytes verbatim",
        );

        let wire_best_effort =
            encode_frame_with_declare(0, build_declare_kexpr(7, "demo/test").unwrap(), false);
        assert_eq!(
            wire_best_effort[0],
            wire_const::T_MID_FRAME,
            "best-effort Frame must omit FLAG_T_FRAME_R",
        );
    }

    /// R121j-2 — `encode_frame_with_response_final` produces the
    /// same Frame envelope wrap as the other `encode_frame_with_*`
    /// helpers, with `ResponseFinal.wire()` as the payload bytes.
    /// Reliable / best-effort header-flag behaviour mirrors the
    /// other three helpers; the production action layer hard-codes
    /// reliable=true but the helper accepts the flag for fuzz /
    /// negative-test paths.
    #[cfg(feature = "codec-response-final")]
    #[test]
    fn encode_frame_with_response_final_wraps_in_frame_envelope() {
        let rf = build_response_final(42);
        let rf_bytes = rf.wire();

        let wire_reliable = encode_frame_with_response_final(0, build_response_final(42), true);
        assert_eq!(
            wire_reliable[0],
            wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME,
            "reliable Frame must set FLAG_T_FRAME_R on the parent header",
        );
        assert_eq!(wire_reliable[1], 0x00, "sn=0 VLE = single byte 0x00");
        assert_eq!(
            &wire_reliable[2..],
            rf_bytes.as_slice(),
            "Frame body tail must be ResponseFinal.wire() bytes verbatim",
        );

        let wire_best_effort = encode_frame_with_response_final(0, build_response_final(42), false);
        assert_eq!(
            wire_best_effort[0],
            wire_const::T_MID_FRAME,
            "best-effort Frame must omit FLAG_T_FRAME_R",
        );
    }

    /// R121j-3 — `encode_frame_with_response` produces the same
    /// `[parent_flags | T_MID_FRAME]` + `Frame.wire()` wrapping as
    /// the other helpers, with `Response.wire()` as the inner
    /// payload bytes. Reply data delivery defaults to reliable.
    #[cfg(feature = "codec-response")]
    #[test]
    fn encode_frame_with_response_wraps_response_in_frame_envelope() {
        let response = build_response_reply_literal(42, "k", b"v").unwrap();
        let response_bytes = response.wire();

        let wire_reliable = encode_frame_with_response(
            0,
            build_response_reply_literal(42, "k", b"v").unwrap(),
            true,
        );
        assert_eq!(
            wire_reliable[0],
            wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME,
            "reliable Frame must set FLAG_T_FRAME_R",
        );
        assert_eq!(wire_reliable[1], 0x00, "sn=0 VLE = 0x00");
        assert_eq!(
            &wire_reliable[2..],
            response_bytes.as_slice(),
            "Frame body tail must be Response.wire() bytes verbatim",
        );

        let wire_best_effort = encode_frame_with_response(
            0,
            build_response_reply_literal(42, "k", b"v").unwrap(),
            false,
        );
        assert_eq!(
            wire_best_effort[0],
            wire_const::T_MID_FRAME,
            "best-effort Frame must omit FLAG_T_FRAME_R",
        );
    }

    #[cfg(feature = "codec-request")]
    #[test]
    fn encode_frame_with_request_wraps_request_in_frame_envelope() {
        let request = build_request_query(42, 7, None).unwrap();
        let request_bytes = request.wire();

        let wire_reliable =
            encode_frame_with_request(0, build_request_query(42, 7, None).unwrap(), true);
        assert_eq!(
            wire_reliable[0],
            wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME,
            "reliable Frame must set FLAG_T_FRAME_R on the parent header",
        );
        assert_eq!(wire_reliable[1], 0x00, "sn=0 VLE = single byte 0x00");
        assert_eq!(
            &wire_reliable[2..],
            request_bytes.as_slice(),
            "Frame body tail must be Request.wire() bytes verbatim",
        );

        let wire_best_effort =
            encode_frame_with_request(0, build_request_query(42, 7, None).unwrap(), false);
        assert_eq!(
            wire_best_effort[0],
            wire_const::T_MID_FRAME,
            "best-effort Frame must omit FLAG_T_FRAME_R",
        );
    }
}

#[cfg(all(test, feature = "transport-fragmentation"))]
mod fragment_tests {
    use super::{fragment_body, fragment_count};
    use crate::inbound::{parse_inbound, InboundFrame};
    use alloc::vec::Vec;
    use wz_codecs::wire_const;

    /// `fragment_count` ceils the body over `mtu - FRAG_HEADER_BUDGET`
    /// (1 header byte + the 10-byte max-VLE SN budget = 11), so the count is
    /// known before the SN block is reserved.
    #[test]
    fn fragment_count_ceils_body_over_chunk_capacity() {
        // mtu 64 -> chunk = 64 - 11 = 53.
        assert_eq!(
            fragment_count(53, 64, false),
            1,
            "one full chunk = one fragment"
        );
        assert_eq!(
            fragment_count(54, 64, false),
            2,
            "one byte over = two fragments"
        );
        assert_eq!(fragment_count(200, 64, false), 4, "ceil(200 / 53) = 4");
    }

    /// A >MTU body fragments into `T_MID_FRAGMENT` frames that each fit the
    /// MTU, carry consecutive SNs from the base, set M (more) on every
    /// fragment but the last and R per the channel, and whose payloads
    /// concatenate back to the original body — verified through the real
    /// `parse_inbound` decode, not a hand-rolled split.
    #[test]
    fn fragment_body_round_trips_through_parse_inbound() {
        let body: Vec<u8> = (0..200u32).map(|i| (i * 7) as u8).collect();
        let mtu = 64usize;
        let base_sn = 7u64;

        let frames = fragment_body(
            &body,
            /*reliable=*/ true,
            mtu,
            base_sn,
            crate::sn::mask_from_res(0x02),
            None,
        );
        assert_eq!(frames.len(), fragment_count(body.len(), mtu, false));
        assert!(frames.len() > 1, "200 bytes at mtu 64 must fragment");

        let mut reassembled = Vec::new();
        for (i, frame) in frames.iter().enumerate() {
            assert!(
                frame.len() <= mtu,
                "fragment {i} is {} bytes, exceeds mtu {mtu}",
                frame.len()
            );
            assert_eq!(
                frame[0] & 0x1f,
                wire_const::T_MID_FRAGMENT,
                "fragment {i} header MID must be T_MID_FRAGMENT",
            );
            let InboundFrame::Fragment {
                reliable,
                sn,
                more,
                payload,
                ..
            } = parse_inbound(frame).expect("parse fragment")
            else {
                panic!("frame {i} did not decode as a Fragment");
            };
            assert!(reliable, "R flag must be set on a reliable chain");
            assert_eq!(
                sn,
                base_sn + i as u64,
                "fragment SNs must be consecutive from the base",
            );
            let is_last = i + 1 == frames.len();
            assert_eq!(
                more, !is_last,
                "M (more) is set on every fragment but the last"
            );
            reassembled.extend_from_slice(&payload);
        }
        assert_eq!(
            reassembled, body,
            "fragment payloads must concatenate back to the original body",
        );
    }

    /// R311y206 — the FIRST fragment of a chain carries the `FRAGMENT_FIRST`
    /// marker (header `Z` bit + a `0x02` ext byte after `VLE(sn)`, before the
    /// payload); no subsequent fragment does. zenoh-pico silently drops a
    /// marker-less chain on a protocol-patch >= 1 session (which wz always
    /// advertises), so this is the interop-load-bearing bit the binary-dep
    /// wz->pico e2e (`wz_fragment_tx_to_pico_zsub`) exercises over a real
    /// socket — pinned here on a host lane so a `first`-handling regression
    /// fails WITHOUT the pico CLI. Also asserts the marked first fragment
    /// stays `<= mtu` (the ext rides the VLE-reserve slack).
    #[test]
    fn fragment_body_marks_only_the_first_fragment() {
        let body: Vec<u8> = (0..200u32).map(|i| (i * 7) as u8).collect();
        let mtu = 64usize;
        let base_sn = 7u64; // VLE width 1 -> the ext byte lands at wire[2].
        let frames = fragment_body(
            &body,
            true,
            mtu,
            base_sn,
            crate::sn::mask_from_res(0x02),
            None,
        );
        assert!(
            frames.len() >= 2,
            "200B at mtu 64 must be a multi-fragment chain"
        );

        // First fragment: Z bit set + the 0x02 ext byte right after VLE(sn).
        let first = &frames[0];
        assert!(
            first.len() <= mtu,
            "the marked first fragment still fits mtu"
        );
        assert_ne!(
            first[0] & wire_const::FLAG_T_Z,
            0,
            "first fragment header must set Z (ext chain present)"
        );
        assert_eq!(
            first[2],
            super::FRAGMENT_FIRST_EXT_HEADER,
            "first fragment carries the 0x02 FRAGMENT_FIRST ext after VLE(sn)"
        );
        let InboundFrame::Fragment {
            has_ext,
            sn,
            payload,
            ..
        } = parse_inbound(first).expect("parse first fragment")
        else {
            panic!("first frame is not a Fragment");
        };
        assert!(has_ext, "first fragment decodes with the ext chain present");
        assert_eq!(sn, base_sn, "first fragment SN is the base");
        // chunk = mtu - FRAG_HEADER_BUDGET = 64 - 11 = 53; the decoded payload
        // (ext already stripped by parse_inbound) is the leading body chunk.
        assert_eq!(
            &payload[..],
            &body[..53],
            "first fragment payload is the leading chunk, ext stripped"
        );

        // Every subsequent fragment: no Z, no ext.
        for (i, frame) in frames.iter().enumerate().skip(1) {
            assert_eq!(
                frame[0] & wire_const::FLAG_T_Z,
                0,
                "fragment {i} (not first) must NOT set Z"
            );
            let InboundFrame::Fragment { has_ext, .. } =
                parse_inbound(frame).expect("parse fragment")
            else {
                panic!("frame {i} is not a Fragment");
            };
            assert!(!has_ext, "fragment {i} (not first) has no ext chain");
        }
    }

    /// R311kb — a chain whose reserved block crosses the ring seam walks
    /// `mask -> 0` (zenoh-pico `_z_sn_increment` parity); the prior
    /// unmasked `wrapping_add(1)` emitted `mask + 1` there, which the
    /// peer's ring-consecutive gate rejects. A raw (un-masked) reserved
    /// base projects onto the ring too.
    #[test]
    fn fragment_body_sn_walk_wraps_at_ring_seam() {
        use super::super::sn;
        let mask = sn::mask_from_res(0x00); // 7-bit ring, seam at 127
        let body = alloc::vec![0x5Au8; 200]; // 4 fragments at mtu 64
                                             // Raw counter base one whole ring above 126: projects to 126.
        let frames = fragment_body(&body, true, 64, 126 + (mask + 1), mask, None);
        assert_eq!(frames.len(), 4);
        let sns: Vec<u64> = frames
            .iter()
            .map(|f| {
                let InboundFrame::Fragment { sn, .. } = parse_inbound(f).expect("parse fragment")
                else {
                    panic!("not a Fragment");
                };
                sn
            })
            .collect();
        assert_eq!(
            sns,
            alloc::vec![126, 127, 0, 1],
            "the SN walk must wrap mask -> 0 on the ring"
        );
    }

    /// A best-effort chain clears the R bit on every fragment.
    #[test]
    fn fragment_body_best_effort_clears_r_flag() {
        let body = alloc::vec![0xABu8; 120];
        let frames = fragment_body(
            &body,
            /*reliable=*/ false,
            64,
            0,
            crate::sn::mask_from_res(0x02),
            None,
        );
        assert!(frames.len() > 1, "120 bytes at mtu 64 must fragment");
        for frame in &frames {
            assert_eq!(
                frame[0] & wire_const::FLAG_T_FRAGMENT_R,
                0,
                "best-effort fragment must clear the R bit",
            );
        }
    }

    /// R311ko — a frame that fits the budget passes through untouched and
    /// mints nothing beyond the frame SN the caller already drew.
    #[test]
    fn multicast_frame_passes_through_when_it_fits() {
        use crate::qos::Priority;
        let mut tx_sn = crate::sn::MulticastTxConduits::new(crate::sn::mask_from_res(0x02));
        let sn = tx_sn.mint(Priority::DEFAULT, true);
        let mut frame = Vec::new();
        super::begin_frame(&mut frame, sn, super::frame_flags(true), None);
        frame.extend_from_slice(&[0xCD; 16]);
        let after_mint = tx_sn.clone();
        // DEFAULT / non-qos re-frame: ext_qos = None, byte-identical to pre-qos.
        let out =
            super::multicast_frame_or_fragments(frame.clone(), sn, true, 64, &mut tx_sn, None);
        assert_eq!(out, alloc::vec![frame], "a fitting frame passes through");
        assert_eq!(tx_sn, after_mint, "no follow-on mint for a fitting frame");
    }

    /// R311ko — an oversize frame re-frames as a fragment chain whose
    /// first SN IS the frame's already-minted SN (zenoh-pico
    /// `_z_transport_tx_send_fragment` passes the frame `sn` through as
    /// `first_sn`), whose payloads concatenate back to the frame's
    /// network-message body (sliced past the 2-byte-VLE SN prefix), and
    /// whose follow-on mints advance the channel to one past the chain.
    #[test]
    fn multicast_oversize_chains_from_the_minted_frame_sn() {
        use crate::qos::Priority;
        let mtu = 64usize;
        let mut tx_sn = crate::sn::MulticastTxConduits::new(crate::sn::mask_from_res(0x02));
        tx_sn.default_conduit_mut().next_reliable = 200; // 2-byte VLE: pins the body-offset slice
        let sn = tx_sn.mint(Priority::DEFAULT, true);
        let body: Vec<u8> = (0..200u32).map(|i| (i * 3) as u8).collect();
        let mut frame = Vec::new();
        super::begin_frame(&mut frame, sn, super::frame_flags(true), None);
        frame.extend_from_slice(&body);

        let mask = tx_sn.mask();
        let frames = super::multicast_frame_or_fragments(frame, sn, true, mtu, &mut tx_sn, None);
        assert_eq!(frames.len(), fragment_count(body.len(), mtu, false));
        assert!(frames.len() > 1, "200 bytes at mtu 64 must fragment");
        assert_eq!(
            tx_sn.advertise_default().next_reliable,
            (sn + frames.len() as u64) & mask,
            "the chain consumes count SNs total (frame mint + count-1 follow-ons)",
        );
        assert_eq!(
            tx_sn.advertise_default().next_best_effort,
            0,
            "a reliable chain leaves the other channel untouched",
        );

        let mut reassembled = Vec::new();
        let mut expect_sn = sn;
        for (i, frag) in frames.iter().enumerate() {
            assert!(frag.len() <= mtu, "fragment {i} exceeds mtu");
            let InboundFrame::Fragment {
                reliable,
                sn: frag_sn,
                more,
                payload,
                ..
            } = parse_inbound(frag).expect("parse fragment")
            else {
                panic!("frame {i} did not decode as a Fragment");
            };
            assert!(reliable, "R flag rides the channel");
            assert_eq!(frag_sn, expect_sn, "fragment {i} SN must walk the ring");
            assert_eq!(more, i + 1 < frames.len(), "M on every fragment but last");
            reassembled.extend_from_slice(&payload);
            expect_sn = crate::sn::increment(mask, expect_sn);
        }
        assert_eq!(reassembled, body, "payloads concatenate back to the body");
    }
}

// R311y215 — the ext_qos wire round-trip: the priority a QoS Frame/Fragment
// encodes is exactly the one `parse_inbound` recovers, and a DEFAULT frame is
// byte-identical to the pre-QoS wire. `transport-qos` pulls `codec-frame`, so
// `parse_inbound` (the real decoder) is in scope.
#[cfg(all(test, feature = "transport-qos"))]
mod qos_wire_tests {
    use super::*;
    use crate::inbound::{parse_inbound, InboundFrame};
    use crate::qos::Priority;

    /// R311y227 — an oversize QoS MULTICAST frame re-frames as a fragment chain
    /// that carries the `ext_qos` on EVERY fragment AND mints its follow-on SNs on
    /// the frame's PRIORITY conduit (not DEFAULT) — the oversize *prioritized*
    /// multicast Push the R311y227 review flagged as untested at the multicast
    /// layer (it was covered only transitively via the unicast `fragment_body`).
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn multicast_qos_oversize_chains_carry_ext_qos_on_the_priority_conduit() {
        use crate::sn::{mask_from_res, MulticastTxConduits};
        let mtu = 64usize;
        let mut tx = MulticastTxConduits::new(mask_from_res(0x02));
        // Mint the head on the RealTime reliable conduit (SN 0).
        let sn = tx.mint(Priority::RealTime, true);
        let body: Vec<u8> = (0..200u32).map(|i| (i * 3) as u8).collect();
        let mut frame = Vec::new();
        super::begin_frame(
            &mut frame,
            sn,
            super::frame_flags(true),
            Some(Priority::RealTime),
        );
        frame.extend_from_slice(&body);
        let mask = tx.mask();
        let frames = super::multicast_frame_or_fragments(
            frame,
            sn,
            true,
            mtu,
            &mut tx,
            Some(Priority::RealTime),
        );
        assert!(frames.len() > 1, "200 bytes at mtu 64 must fragment");
        // Follow-on SNs minted on the RealTime conduit; DEFAULT conduit untouched.
        assert_eq!(
            tx.advertise_per_priority()[Priority::RealTime as usize].next_reliable,
            (sn + frames.len() as u64) & mask,
            "the chain's follow-on mints ride the RealTime conduit"
        );
        assert_eq!(
            tx.advertise_default().next_reliable,
            0,
            "the DEFAULT conduit is untouched by a RealTime fragment chain"
        );
        // Every fragment decodes with the RealTime band (ext re-emitted per chunk).
        let mut reassembled = Vec::new();
        for frag in &frames {
            assert!(frag.len() <= mtu, "fragment fits mtu");
            let InboundFrame::Fragment {
                priority, payload, ..
            } = parse_inbound(frag).expect("fragment decodes")
            else {
                panic!("expected a Fragment");
            };
            assert_eq!(
                priority,
                Priority::RealTime,
                "each fragment carries the ext_qos band"
            );
            reassembled.extend_from_slice(&payload);
        }
        assert_eq!(
            reassembled, body,
            "the qos fragment payloads concatenate back to the body"
        );
    }

    /// A non-DEFAULT priority Frame sets the Z flag and carries a z64 ext_qos
    /// (`[0x31][VLE(priority)]`) after `VLE(sn)`; `parse_inbound` recovers the
    /// priority, reliability, sn, and has_ext. Empty payload keeps the assertion
    /// on the ext bytes.
    #[test]
    fn frame_ext_qos_round_trips_priority() {
        let wire =
            encode_frame_envelope(7, frame_flags(true), 0, Some(Priority::RealTime), |_sink| {
                Ok(())
            });
        assert_ne!(
            wire[0] & wire_const::FLAG_T_Z,
            0,
            "a QoS Frame sets the ext-chain Z flag"
        );
        assert_eq!(wire[1], 0x07, "VLE(sn=7) is one byte");
        assert_eq!(wire[2], 0x31, "ext_qos header = id0x1 | M | ENC_Z64");
        assert_eq!(
            wire[3],
            Priority::RealTime.wire_byte(),
            "z64 body = VLE(priority)"
        );
        let InboundFrame::Frame {
            priority,
            reliable,
            sn,
            has_ext,
            ..
        } = parse_inbound(&wire).expect("parse QoS Frame")
        else {
            panic!("not a Frame");
        };
        assert_eq!(priority, Priority::RealTime, "priority round-trips");
        assert!(reliable);
        assert_eq!(sn, 7);
        assert!(has_ext);
    }

    /// A DEFAULT-priority frame (`ext_qos = None`) is byte-identical to the
    /// pre-QoS wire — no Z flag, no ext bytes — and decodes back to DEFAULT.
    #[test]
    fn default_priority_frame_is_byte_identical_and_decodes_default() {
        let wire = encode_frame_envelope(7, frame_flags(true), 0, None, |_sink| Ok(()));
        assert_eq!(
            wire,
            alloc::vec![wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME, 0x07],
            "DEFAULT frame = [R|FRAME][VLE(sn)] with NO ext (pre-QoS wire)"
        );
        let InboundFrame::Frame {
            priority, has_ext, ..
        } = parse_inbound(&wire).expect("parse DEFAULT Frame")
        else {
            panic!("not a Frame");
        };
        assert_eq!(priority, Priority::DEFAULT);
        assert!(!has_ext, "no ext chain on a DEFAULT frame");
    }

    /// R311y215 (SN-safety F3) — a QoS fragment chain carries the ext_qos on
    /// EVERY fragment: `parse_inbound` recovers the SAME priority off each one
    /// (frag 0 chains it ahead of the FRAGMENT_FIRST marker), every fragment
    /// still fits the MTU, and the decoded payloads concatenate back to the
    /// original body. Gated on `transport-fragmentation` (the `fragment_body`
    /// gate) — it implies `reassembly` (the `InboundFrame::Fragment` gate).
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn fragment_qos_chain_carries_priority_on_every_fragment() {
        let body: Vec<u8> = (0..200u32).map(|i| (i * 7) as u8).collect();
        let mtu = 64usize;
        let frames = fragment_body(
            &body,
            /*reliable=*/ true,
            mtu,
            /*base_sn=*/ 7,
            crate::sn::mask_from_res(0x02),
            Some(Priority::InteractiveHigh),
        );
        assert!(frames.len() > 1, "200B at mtu 64 must fragment");
        let mut reassembled = Vec::new();
        for (i, frame) in frames.iter().enumerate() {
            assert!(
                frame.len() <= mtu,
                "QoS fragment {i} still fits the mtu (ext_qos rides the budget)"
            );
            let InboundFrame::Fragment {
                priority,
                has_ext,
                more,
                sn,
                reliable,
                payload,
                ..
            } = parse_inbound(frame).expect("parse QoS fragment")
            else {
                panic!("frame {i} is not a Fragment");
            };
            assert_eq!(
                priority,
                Priority::InteractiveHigh,
                "every fragment carries the chain priority (F3)"
            );
            assert!(has_ext, "every QoS fragment has an ext chain");
            assert!(reliable, "R rides every fragment");
            assert_eq!(sn, 7 + i as u64, "SNs consecutive from the base");
            assert_eq!(
                more,
                i + 1 < frames.len(),
                "M on every fragment but the last"
            );
            reassembled.extend_from_slice(&payload);
        }
        assert_eq!(
            reassembled, body,
            "QoS fragment payloads (both exts stripped by the decoder) reassemble to the body"
        );
    }

    /// R311y215 regression (3-agent review finding) — re-fragmenting an OVERSIZE
    /// QoS Frame must strip the FRAME's own ext_qos from the body before
    /// fragmenting: each fragment re-frames its OWN ext_qos, so the reassembled
    /// payloads are the NetworkMessage batch ALONE, not `[0x31][priority] +
    /// batch`. Exercises the `frame_wire_body(Some(priority)) -> fragment_body`
    /// path the immediate / batch oversize emit takes
    /// (`session_actions::emit_frame_or_fragments`). Before the fix the frame's
    /// 2 stale ext bytes prepended to the reassembled batch and broke the peer's
    /// `parse_frame_payload` (`0x31 & 0x1F` is not a valid network MID).
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn oversize_qos_frame_refragment_strips_frame_ext_qos() {
        let batch: Vec<u8> = (0..200u32).map(|i| (i * 3 + 1) as u8).collect();
        let sn = 7u64;
        let priority = Priority::DataHigh;
        // Encode the WHOLE QoS Frame exactly as dispatch does:
        // [hdr|Z][VLE(sn)][ext_qos][batch].
        let mut frame = Vec::new();
        begin_frame(&mut frame, sn, frame_flags(true), Some(priority));
        frame.extend_from_slice(&batch);
        assert_ne!(frame[0] & wire_const::FLAG_T_Z, 0, "the QoS Frame sets Z");
        assert_eq!(frame[2], 0x31, "ext_qos header rides the frame");
        // The re-frame body must be the BATCH alone — header + VLE(sn) + the
        // frame's ext_qos all stripped.
        let body = frame_wire_body(&frame, sn, Some(priority));
        assert_eq!(
            body,
            &batch[..],
            "frame_wire_body must strip the frame ext_qos, not just header+sn"
        );
        // Re-fragment at a small MTU and reassemble: payloads == batch, with NO
        // 0x31 contamination, and each fragment carries the priority.
        let mtu = 64usize;
        let frames = fragment_body(
            body,
            true,
            mtu,
            sn,
            crate::sn::mask_from_res(0x02),
            Some(priority),
        );
        assert!(frames.len() > 1, "200B at mtu 64 must fragment");
        let mut reassembled = Vec::new();
        for f in &frames {
            let InboundFrame::Fragment {
                priority: p,
                payload,
                ..
            } = parse_inbound(f).expect("parse fragment")
            else {
                panic!("not a fragment");
            };
            assert_eq!(p, priority, "each fragment carries the priority");
            reassembled.extend_from_slice(&payload);
        }
        assert_eq!(
            reassembled, batch,
            "reassembled payloads are the batch ALONE, not [0x31,priority]+batch"
        );
    }
}

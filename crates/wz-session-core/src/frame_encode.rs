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

#[cfg(feature = "codec-declare")]
use wz_codecs::declare::{Declare, DeclareOwned};
use wz_codecs::interest::{Interest, InterestOwned};
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

/// R311jq — write the FRAME prefix (header byte + `VLE(sn)`) into `buf`.
/// The single home of the prefix wire format, shared by the
/// immediate-path [`encode_frame_envelope`] and the batching open-frame
/// writer in `SessionLinkActions`.
///
/// The `VLE(sn)` loop is bit-identical to `Frame::encode`'s sn block
/// — it IS the wire format (zenoh-pico VLE base-128 encoding per
/// `vendor/zenoh-pico/src/protocol/codec/core.c`), not consumer-tunable
/// logic.
pub(crate) fn begin_frame(buf: &mut Vec<u8>, sn: u64, parent_flags: u8) {
    buf.push(parent_flags | wire_const::T_MID_FRAME);
    let mut sink = VecSink::new(buf);
    let mut vle = sn;
    while vle >= 0x80 {
        sink.write_u8((vle as u8 & 0x7F) | 0x80)
            .expect("VecSink is infallible");
        vle >>= 7;
    }
    sink.write_u8(vle as u8).expect("VecSink is infallible");
}

/// R311jq — derive the link-driver [`Reliability`] of an already-encoded
/// outbound `T_MID_FRAME` from its header's R flag. The batch flush
/// paths re-emit a frame that was opened by an earlier message, so the
/// channel must come from the frame bytes, not from the
/// currently-dispatched message (zenoh-pico appends mixed-reliability
/// messages into whatever frame is open — the OPENING message's flag
/// governs; `tx.c _z_transport_tx_send_n_msg_inner` mints the header
/// only when the buffer is empty).
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
    payload_encode: P,
) -> Vec<u8>
where
    P: FnOnce(&mut VecSink<'_>) -> Result<(), CodecError>,
{
    let mut wire = Vec::with_capacity(1 + 10 + worst_case_payload);
    begin_frame(&mut wire, sn, parent_flags);
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
    encode_frame_envelope(
        sn,
        frame_flags(reliable),
        Push::MAX_ENCODED_BYTES,
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
/// cfg = fragmentation AND the wire-emit union: the only consumer is the
/// fragment body-slice in `emit_frame_or_fragments`, which exists when at
/// least one network-message sender is compiled — a no-sender subset must
/// not carry the dead symbol (`-D warnings` lanes). (R311jq: the batching
/// append no longer slices — it sink-encodes into the open frame
/// directly, so batching dropped out of this cfg.)
#[cfg(all(
    feature = "transport-fragmentation",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-final",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
pub(crate) fn vle_width(sn: u64) -> usize {
    let (mut width, mut v) = (1usize, sn);
    while v >= 0x80 {
        v >>= 7;
        width += 1;
    }
    width
}

/// Conservative per-fragment header budget: 1 flags byte + the maximum u64
/// VLE width (10). Sizing chunks against the *maximum* SN width (rather than
/// each fragment's actual SN width) makes the fragment count computable
/// *before* the SN block is reserved, and guarantees every emitted fragment is
/// `<= mtu` whatever its SN. The few unused payload bytes per fragment are
/// negligible against a multi-KB body.
#[cfg(feature = "transport-fragmentation")]
const FRAG_HEADER_BUDGET: usize = 1 + 10;

/// Per-fragment payload capacity at this `mtu`. Floored at 1 so a pathological
/// `mtu <= FRAG_HEADER_BUDGET` still terminates (one body byte per fragment)
/// rather than dividing by zero; production `mtu` is the negotiated batch size,
/// far above the header budget.
#[cfg(feature = "transport-fragmentation")]
fn fragment_chunk_size(mtu: usize) -> usize {
    mtu.saturating_sub(FRAG_HEADER_BUDGET).max(1)
}

/// Number of `T_MID_FRAGMENT` frames a `body_len`-byte network message splits
/// into at this `mtu`. The caller reserves exactly this many consecutive SNs
/// before calling [`fragment_body`].
#[cfg(feature = "transport-fragmentation")]
pub(crate) fn fragment_count(body_len: usize, mtu: usize) -> usize {
    let chunk = fragment_chunk_size(mtu);
    // ceil(body_len / chunk), min 1 (an empty body still emits one final
    // fragment — though the oversize precondition means body is never empty).
    body_len.div_ceil(chunk).max(1)
}

/// Split a serialized network-message `body` into the `T_MID_FRAGMENT` wire
/// frames, SNs drawn from the contiguous block `base_sn ..= base_sn + N - 1`
/// (where `N == fragment_count(body.len(), mtu)`). Every fragment but the last
/// carries the M (more) flag; R (reliable) is set per `reliable`. zenoh-pico
/// `_z_transport_tx_send_fragment_inner` parity.
#[cfg(feature = "transport-fragmentation")]
pub fn fragment_body(body: &[u8], reliable: bool, mtu: usize, base_sn: u64) -> Vec<Vec<u8>> {
    let chunk = fragment_chunk_size(mtu);
    let mut out = Vec::with_capacity(fragment_count(body.len(), mtu));
    let mut off = 0usize;
    let mut sn = base_sn;
    loop {
        let end = core::cmp::min(off + chunk, body.len());
        let more = end < body.len();
        out.push(build_fragment_wire(sn, &body[off..end], reliable, more));
        off = end;
        if !more {
            break;
        }
        sn = sn.wrapping_add(1);
    }
    out
}

/// Encode one `T_MID_FRAGMENT` wire frame: a `[flags | T_MID_FRAGMENT]`
/// transport-message header byte (R/M ride the header) followed by the
/// `wz_codecs::fragment` codec body (`VLE(sn) + tail payload`). The body is
/// the byte-verified SSOT — `layer3_fragment.rs` checks `Fragment::encode`
/// against zenoh-pico `_z_fragment_encode`, and `inbound.rs` decodes the
/// symmetric shape — so production TX shares it rather than re-deriving the
/// VLE wire. Mirrors zenoh-pico, where `_z_transport_message_encode` writes the
/// header and the fragment codec writes the body.
#[cfg(feature = "transport-fragmentation")]
fn build_fragment_wire(sn: u64, payload: &[u8], reliable: bool, more: bool) -> Vec<u8> {
    let mut flags = 0u8;
    if reliable {
        flags |= wire_const::FLAG_T_FRAGMENT_R;
    }
    if more {
        flags |= wire_const::FLAG_T_FRAGMENT_M;
    }
    let mut wire = Vec::with_capacity(FRAG_HEADER_BUDGET + payload.len());
    wire.push(flags | wire_const::T_MID_FRAGMENT);
    {
        let mut sink = VecSink::new(&mut wire);
        wz_codecs::fragment::Fragment { sn, payload }
            .encode(&mut sink)
            .expect("VecSink is infallible");
    }
    wire
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
        assert_eq!(fragment_count(53, 64), 1, "one full chunk = one fragment");
        assert_eq!(fragment_count(54, 64), 2, "one byte over = two fragments");
        assert_eq!(fragment_count(200, 64), 4, "ceil(200 / 53) = 4");
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

        let frames = fragment_body(&body, /*reliable=*/ true, mtu, base_sn);
        assert_eq!(frames.len(), fragment_count(body.len(), mtu));
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

    /// A best-effort chain clears the R bit on every fragment.
    #[test]
    fn fragment_body_best_effort_clears_r_flag() {
        let body = alloc::vec![0xABu8; 120];
        let frames = fragment_body(&body, /*reliable=*/ false, 64, 0);
        assert!(frames.len() > 1, "120 bytes at mtu 64 must fragment");
        for frame in &frames {
            assert_eq!(
                frame[0] & wire_const::FLAG_T_FRAGMENT_R,
                0,
                "best-effort fragment must clear the R bit",
            );
        }
    }
}

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

/// R121h-perf-bump-3 — single-allocation transport-envelope encode.
/// Composes the parent-flags byte, `VLE(sn)`, and a sink-encoded
/// payload into one growable `Vec`, eliminating the prior
/// `payload.encode_to_vec()` + `Frame.encode_to_vec()` +
/// `wire.extend_from_slice(&body_bytes)` chain (3 allocations per
/// hot-path emit). For typical 1–2 KB payloads the reserved capacity
/// is also dramatically smaller than the 64 KB `Frame::MAX_ENCODED_BYTES`
/// ceiling, since the inner codec's worst-case bound is used directly.
///
/// The `VLE(sn)` loop is bit-identical to `Frame::encode`'s sn block
/// — it IS the wire format (zenoh-pico VLE base-128 encoding per
/// `vendor/zenoh-pico/src/protocol/codec/core.c`), not consumer-tunable
/// logic. Inlining here does not duplicate semantics.
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
    wire.push(parent_flags | wire_const::T_MID_FRAME);
    {
        let mut sink = VecSink::new(&mut wire);
        let mut _vle = sn;
        while _vle >= 0x80 {
            sink.write_u8((_vle as u8 & 0x7F) | 0x80)
                .expect("VecSink is infallible");
            _vle >>= 7;
        }
        sink.write_u8(_vle as u8).expect("VecSink is infallible");
        payload_encode(&mut sink).expect("VecSink is infallible");
    }
    wire
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
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, Response::MAX_ENCODED_BYTES, |sink| {
        response
            .try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    })
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
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, ResponseFinal::MAX_ENCODED_BYTES, |sink| {
        response_final
            .try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    })
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
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, Request::MAX_ENCODED_BYTES, |sink| {
        request
            .try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    })
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
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, Declare::MAX_ENCODED_BYTES, |sink| {
        declare
            .try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    })
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
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, Interest::MAX_ENCODED_BYTES, |sink| {
        interest
            .try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    })
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
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, Push::MAX_ENCODED_BYTES, |sink| {
        push.try_as_borrowed()
            .expect("wz builders emit <=N exts by construction")
            .encode(sink)
    })
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

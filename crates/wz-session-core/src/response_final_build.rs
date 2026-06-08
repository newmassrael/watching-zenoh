// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Outbound RESPONSE-FINAL network-message builder.
//!
//! `build_response_final` constructs the `ResponseFinalOwned` envelope that
//! terminates a multi-Reply sequence. Pure wz-codecs construction — no
//! runtime / no FSM coupling; the transport-`Frame` envelope is applied
//! separately by `frame_encode::encode_frame_with_response_final`.
//!
//! Kept SEPARATE from `response_build` deliberately: that module gates on
//! `codec-response` (the Reply/Err builders), whereas ResponseFinal is its
//! own `codec-response-final` vertical (the two features are independent —
//! a peer may compose ResponseFinal without the Reply/Err response codec).
//! Folding this into `response_build` would force the whole Reply/Err
//! cluster onto a `codec-response-final`-only subset. Hoisted from
//! `wz-runtime-tokio::session_glue` so both runtime profiles share it;
//! alloc + `codec-response-final` gated.

use wz_codecs::response_final::ResponseFinalOwned;

/// R121j-2 — build a `ResponseFinal` network-message that terminates
/// the multi-Reply sequence for `request_id`. Mirrors zenoh-pico
/// `_z_response_final_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/network.c:368-376`:
///
/// ```text
///   [ResponseFinal.header = _Z_MID_N_RESPONSE_FINAL (0x1A)]
///   VLE(request_id)
/// ```
///
/// AP MVP scope: minimal shape only — no Z(extensions) flag, no
/// trailing ExtEntry list. Future rounds that need RF-level
/// extensions (none defined in zenoh-pico today, but the wire format
/// reserves bit 7 for it via the `_Z_FLAG_Z_Z` carrier) extend this
/// helper with an exts-present variant.
///
/// ResponseFinal is a network-message envelope at the same layer as
/// `Declare` and `Request` — its `.encode_to_vec()` output is emitted
/// directly into the Frame payload without an additional wrapper
/// header. The 0x1A MID lives in the `_Z_MID_N_*` network-message
/// namespace (distinct from the inner DECLARE-body 0x1A
/// `_Z_DECL_FINAL_MID`, which is at a different layer).
///
/// `request_id` MUST equal the `rid` from the matching
/// `build_request_query` that opened the Query/Reply session.
pub fn build_response_final(request_id: u64) -> ResponseFinalOwned {
    ResponseFinalOwned {
        // MID 0x1A (_Z_MID_N_RESPONSE_FINAL). Z bit-7 stays clear:
        // minimal shape has no RF-level extensions.
        header: 0x1A,
        request_id,
        extensions: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use wz_codecs_test_support::TestWire;

    /// R121j-1 — `encode_frame_with_request` produces the same
    /// `[parent_flags | T_MID_FRAME]` + `Frame.wire()` wrapping as
    /// the existing `encode_frame_with_push` / `encode_frame_with_declare`
    /// helpers, with `Request.wire()` as the inner payload bytes.
    /// Reliable / best-effort header-flag behaviour mirrors the other
    /// two helpers so the SN-window ordering contract stays uniform
    /// across PUSH / DECLARE / REQUEST outbound paths.
    /// R121j-2 — Wire-byte regression gate: `build_response_final`
    /// emits the zenoh-pico `_z_response_final_encode` shape
    /// (network.c:368-376). Two vectors lock both the single-byte
    /// VLE rid and the multi-byte VLE boundary (rid=200) — the same
    /// boundary R121i-c uses to protect against codegen drift on
    /// the VLE writer's continuation-bit logic.
    #[test]
    fn build_response_final_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — single-byte VLE rid (rid=42).
        let small = build_response_final(42);
        let small_wire = small.wire();
        assert_eq!(
            small_wire,
            vec![
                0x1A, // _Z_MID_N_RESPONSE_FINAL (no Z flag)
                0x2A, // VLE(rid=42)
            ],
            "ResponseFinal small-rid wire bytes must match zenoh-pico reference",
        );

        // Case 2 — multi-byte VLE rid (rid=200, encodes as 0xC8 0x01).
        let large = build_response_final(200);
        let large_wire = large.wire();
        assert_eq!(
            large_wire,
            vec![
                0x1A, 0xC8, // (200 & 0x7F) | 0x80
                0x01, // 200 >> 7
            ],
            "ResponseFinal multi-byte VLE rid wire bytes must match zenoh-pico reference",
        );

        assert_eq!(
            small.header, 0x1A,
            "header carries MID only; Z (bit-7) clear in minimal shape"
        );
        assert_eq!(small.request_id, 42);
        assert!(
            small.extensions.is_none(),
            "minimal shape: no RF-level extensions"
        );
    }
}

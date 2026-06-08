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
#[cfg(feature = "codec-response-final")]
pub fn build_response_final(request_id: u64) -> ResponseFinalOwned {
    ResponseFinalOwned {
        // MID 0x1A (_Z_MID_N_RESPONSE_FINAL). Z bit-7 stays clear:
        // minimal shape has no RF-level extensions.
        header: 0x1A,
        request_id,
        extensions: None,
    }
}

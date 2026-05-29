// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311eg — peer-advertised InitSyn capability snapshot lifted from
//! `wz-runtime-tokio::session_glue`.
//!
//! Pure no_std + no_alloc value type (three integer fields, `Copy`) plus
//! its `from_init_syn` decoder, so it sits on the runtime-agnostic side
//! alongside [`crate::qos`] / [`crate::close_reason`] /
//! [`crate::action_trace`]. The Accepting side reads an InitSyn's `sn_res`
//! byte + optional `batch_size` into this struct to drive the InitAck
//! response capabilities; an MCU profile decodes the same wire fields
//! with the same typed API as the tokio AP profile.
//!
//! The `transport-batching` gate inside `from_init_syn` (whether to honor
//! the peer-advertised `batch_size` or clamp to the full MTU) moves here
//! with the decoder, so `wz-session-core` now owns a `transport-batching`
//! gate-only feature; `wz-runtime-tokio`'s same-named feature forwards to
//! it so the negotiation semantics stay consistent across the workspace.
//! The live `inbound_peer_init_caps: R::Mutex<Option<PeerInitCaps>>` slot
//! is runtime-bound and stays in `session_glue.rs`, which keeps a
//! `pub use` re-export so the `crate::session_glue::PeerInitCaps`
//! callsites resolve unchanged. A DP3 leaf out of `session_glue.rs`.

/// Peer-advertised resolution + batch-size capabilities decoded from an
/// InitSyn. The S-bit (`_Z_FLAG_T_INIT_S`) governs whether the
/// resolution + batch-size fields are present; absent fields fall back
/// to the zenoh-pico defaults (`_z_t_msg_decode` with the S flag
/// clear on InitSyn (zenoh-pico/src/protocol/codec/transport.c:267-269
/// — falls back to `_Z_DEFAULT_RESOLUTION_SIZE = 2` and
/// `_Z_DEFAULT_UNICAST_BATCH_SIZE = 65535`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInitCaps {
    pub seq_num_res: u8,
    pub req_id_res: u8,
    pub batch_size: u16,
}

impl PeerInitCaps {
    /// Decode the InitSyn `sn_res` byte + optional `batch_size`
    /// field per the init_body codec (parent.S=1 carries both,
    /// parent.S=0 falls back to defaults). The `sn_res` byte is
    /// packed `(seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)`
    /// per zenoh-pico transport.c:196-197.
    pub fn from_init_syn(sn_res_byte: Option<u8>, batch_size: Option<u16>) -> Self {
        // R311cb — transport-batching gates the peer-advertised
        // batch_size honoring. cfg-off forces 65535 (full MTU) and
        // ignores the peer's advertised value; honest semantic is
        // "we always batch up to the wire limit and never reduce."
        // The S-bit clear arm always returns 65535 regardless of the
        // feature state — that path is the peer-declined-S baseline,
        // not a negotiation outcome.
        #[cfg(feature = "transport-batching")]
        let honored_batch_size = batch_size.unwrap_or(65535);
        #[cfg(not(feature = "transport-batching"))]
        let honored_batch_size = {
            // transport-batching off: the peer-advertised value is
            // discarded (we clamp to full MTU). Bind it to `_` so the
            // signature stays stable under the gate per the
            // signature-stability principle (R311g1).
            let _ = batch_size;
            65535u16
        };
        match sn_res_byte {
            Some(b) => Self {
                seq_num_res: b & 0x03,
                req_id_res: (b >> 2) & 0x03,
                batch_size: honored_batch_size,
            },
            None => Self {
                // S bit clear → both peer defaults to
                // `_Z_DEFAULT_RESOLUTION_SIZE = 2` and
                // `_Z_DEFAULT_UNICAST_BATCH_SIZE = 65535`.
                seq_num_res: 2,
                req_id_res: 2,
                batch_size: 65535,
            },
        }
    }
}

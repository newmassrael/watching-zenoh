// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311eg — peer-advertised InitSyn capability snapshot lifted from
//! `wz-runtime-tokio::session_glue`.
//!
//! Pure no_std + no_alloc value type (three integer fields, `Copy`) plus
//! its `from_init_body` decoder, so it sits on the runtime-agnostic side
//! alongside [`crate::qos`] / [`crate::close_reason`] /
//! [`crate::action_trace`]. The Accepting side reads an InitSyn's `sn_res`
//! byte + optional `batch_size` into this struct to drive the InitAck
//! response capabilities; an MCU profile decodes the same wire fields
//! with the same typed API as the tokio AP profile.
//!
//! R311kl — the decoder is UNGATED: peer `batch_size` honoring is core
//! transport, zenoh-pico parity (the `param->_batch_size` min adoption
//! and the TX wbuf sizing live outside every `Z_FEATURE_BATCHING` gate,
//! unicast/transport.c:47 + 102 + 135-140; the feature gates only the
//! coalescing machinery, transport.c:35-38). The former R311cb
//! `transport-batching` gate here forced 65535 with the feature off,
//! which made the InitAck ENLARGE a smaller InitSyn advertisement and
//! foreign pico initiators rejected the session (R311fg finding) — the
//! root cause every wz-e2e-* binary worked around by pinning the
//! feature. `transport-batching` now gates exactly what pico's
//! `Z_FEATURE_BATCHING` gates: the TX coalescing window.
//! The live `inbound_peer_init_caps: R::Mutex<Option<PeerInitCaps>>` slot
//! is runtime-bound and stays in `session_glue.rs`, which keeps a
//! `pub use` re-export so the `crate::session_glue::PeerInitCaps`
//! callsites resolve unchanged. A DP3 leaf out of `session_glue.rs`.

/// Peer-advertised resolution + batch-size capabilities decoded from an
/// INIT body — the InitSyn and InitAck share the wire layout
/// (`wz_codecs::init_body`), so the Accepting side decodes the peer's
/// InitSyn advertisement and the Initiating side the acceptor's InitAck
/// final values through one constructor (R311kb). The S-bit
/// (`_Z_FLAG_T_INIT_S`) governs whether the resolution + batch-size
/// fields are present; absent fields fall back to the zenoh-pico
/// defaults (`_z_t_msg_decode` with the S flag clear,
/// zenoh-pico/src/protocol/codec/transport.c:267-269 — falls back to
/// `_Z_DEFAULT_RESOLUTION_SIZE = 2` and
/// `_Z_DEFAULT_UNICAST_BATCH_SIZE = 65535`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInitCaps {
    pub seq_num_res: u8,
    pub req_id_res: u8,
    pub batch_size: u16,
}

/// Decode the raw wire advertisement out of an INIT body — the packed
/// `sn_res` byte (`(seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)`,
/// zenoh-pico transport.c:196-197) plus the optional `batch_size`, with
/// the S-bit-clear defaults applied (`_Z_DEFAULT_RESOLUTION_SIZE = 2`,
/// `_Z_DEFAULT_UNICAST_BATCH_SIZE = 65535`). Returns
/// `(seq_num_res, req_id_res, batch_size)` exactly as the peer put them
/// on the wire: [`PeerInitCaps::from_init_body`] layers the defensive
/// 0-normalization on top, and [`init_ack_exceeds_advertisement`]
/// validates against the unprojected values (a wire 0 must compare as
/// 0, not as the normalized 65535 ceiling).
fn decode_wire_caps(sn_res_byte: Option<u8>, batch_size: Option<u16>) -> (u8, u8, u16) {
    let (seq_num_res, req_id_res) = match sn_res_byte {
        Some(b) => (b & 0x03, (b >> 2) & 0x03),
        None => (2, 2),
    };
    (seq_num_res, req_id_res, batch_size.unwrap_or(65535))
}

/// R311kc — initiator-side InitAck params validation predicate, the
/// zenoh-pico `_Z_ERR_TRANSPORT_OPEN_SN_RESOLUTION` rejection condition
/// (unicast/transport.c:123-140): every InitAck size parameter must be
/// **less than or equal to** the value the initiator advertised in its
/// InitSyn ("Any of the size parameters in the InitAck must be less or
/// equal than the one in the InitSyn"). A peer that ENLARGES
/// `seq_num_res`, `req_id_res`, or `batch_size` returns `true` here and
/// the dispatcher rejects the session instead of adopting the value —
/// before this gate, `min()` negotiation kept our side self-consistent
/// but silently tolerated a non-conforming acceptor (F-b carry).
///
/// Compares the RAW wire advertisement (S-bit-clear defaults applied via
/// [`decode_wire_caps`]), not the projection `PeerInitCaps::
/// from_init_body` stores: its defensive 0-normalization turns a wire 0
/// into the 65535 ceiling, which would falsify exactly the comparison
/// this predicate exists to make (a non-conforming peer's literal 0
/// conforms to any advertisement; a normalized 65535 rarely does).
pub fn init_ack_exceeds_advertisement(
    own_seq_num_res: u8,
    own_req_id_res: u8,
    own_batch_size: u16,
    sn_res_byte: Option<u8>,
    batch_size: Option<u16>,
) -> bool {
    let (peer_seq, peer_req, peer_batch) = decode_wire_caps(sn_res_byte, batch_size);
    peer_seq > own_seq_num_res || peer_req > own_req_id_res || peer_batch > own_batch_size
}

impl PeerInitCaps {
    /// Decode the INIT-body `sn_res` byte + optional `batch_size`
    /// field per the init_body codec (parent.S=1 carries both,
    /// parent.S=0 falls back to defaults; the layout is shared by
    /// InitSyn and InitAck). The `sn_res` byte is packed
    /// `(seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)`
    /// per zenoh-pico transport.c:196-197.
    pub fn from_init_body(sn_res_byte: Option<u8>, batch_size: Option<u16>) -> Self {
        // R311kj — ONE wire decoder: the raw triple comes from
        // [`decode_wire_caps`] (S-clear defaults applied), and this
        // constructor layers ONE projection on top: a wire 0
        // normalizes to the 65535 ceiling defensively. wz itself never
        // emits 0 any more (`SessionInitParams::effective_batch_size`
        // is the advertisement SSOT), so a 0 here is a pre-R311kj wz
        // or a non-conforming peer, and "unset" beats a zero TX
        // budget. R311kl — the honoring itself is unconditional (core
        // transport, pico parity); see the module doc.
        let (seq_num_res, req_id_res, wire_batch) = decode_wire_caps(sn_res_byte, batch_size);
        let batch_size = match wire_batch {
            0 => 65535,
            n => n,
        };
        Self {
            seq_num_res,
            req_id_res,
            batch_size,
        }
    }
}

// ── R311kc init-ack params validation truth table (feature-independent:
//    the predicate compares raw wire values, so it runs in every lane) ──
#[cfg(test)]
mod init_ack_validation_tests {
    use super::*;

    /// Equal-to-advertisement InitAck passes — the conforming acceptor
    /// echoes capped values, and `min()` adoption proceeds.
    #[test]
    fn init_ack_equal_caps_pass() {
        // own seq=1 req=2 batch=1024; peer echoes exactly that.
        let sn_res = Some(0x09); // seq 1 | (req 2 << 2)
        assert!(!init_ack_exceeds_advertisement(
            1,
            2,
            1024,
            sn_res,
            Some(1024)
        ));
        // strictly smaller also passes (acceptor capped further down).
        assert!(!init_ack_exceeds_advertisement(
            1,
            2,
            1024,
            Some(0x04),
            Some(512)
        ));
    }

    /// Each field independently triggers the rejection — pico checks the
    /// three parameters separately (unicast/transport.c:123-140).
    #[test]
    fn init_ack_each_enlarged_field_rejects() {
        // seq_num_res enlarged: peer seq 2 > own 1.
        assert!(init_ack_exceeds_advertisement(
            1,
            2,
            1024,
            Some(0x0A),
            Some(1024)
        ));
        // req_id_res enlarged: peer req 3 > own 2.
        assert!(init_ack_exceeds_advertisement(
            1,
            2,
            1024,
            Some(0x0D),
            Some(1024)
        ));
        // batch_size enlarged: peer 2048 > own 1024.
        assert!(init_ack_exceeds_advertisement(
            1,
            2,
            1024,
            Some(0x09),
            Some(2048)
        ));
    }

    /// S-bit-clear InitAck decodes to the pico defaults (2 / 2 / 65535)
    /// before the comparison — exactly the values `_z_t_msg_decode` falls
    /// back to, so a defaults-vs-defaults handshake passes and a
    /// smaller-than-default advertisement rejects the silent fallback.
    #[test]
    fn init_ack_s_clear_defaults_compared() {
        // own advertised the defaults: peer's S-clear reply conforms.
        assert!(!init_ack_exceeds_advertisement(2, 2, 65535, None, None));
        // own advertised seq_num_res=1: an S-clear reply means the peer
        // adopted the DEFAULT 2 > 1 — non-conforming, reject.
        assert!(init_ack_exceeds_advertisement(1, 2, 65535, None, None));
        // own advertised batch 1024: S-clear default 65535 > 1024, reject.
        assert!(init_ack_exceeds_advertisement(2, 2, 1024, None, None));
    }
}

// ── R311kl core honoring (feature-independent) ──
//
// `from_init_body` honors the peer-advertised `batch_size` in EVERY
// build — the R311cb `transport-batching` gate here was removed because
// it broke foreign interop with the feature off (the InitAck enlarged a
// smaller InitSyn advertisement and pico rejected the session, R311fg).
// This replaces the retired OFF-arm NEG (`peer_batch_size_discarded_
// when_transport_batching_off`), which pinned exactly the projection
// R311kl removed; it runs ungated in the isolated
// `cargo test -p wz-session-core` lanes (C1c/d/e) AND the workspace
// lane, so the honoring is pinned on both sides of the feature.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_batch_size_honored_in_every_build() {
        // sn_res 0x09 = seq 1 | (req 2 << 2); peer advertises batch 1024.
        let caps = PeerInitCaps::from_init_body(Some(0x09), Some(1024));
        assert_eq!(caps.seq_num_res, 1, "packed sn_res decodes");
        assert_eq!(caps.req_id_res, 2, "packed sn_res decodes");
        assert_eq!(
            caps.batch_size, 1024,
            "peer-advertised batch_size is honored unconditionally \
             (core transport, pico parity — R311kl)"
        );
    }

    #[test]
    fn wire_zero_batch_size_normalizes_to_ceiling() {
        // R311kj defensive projection survives the R311kl ungate: a
        // non-conforming wire 0 must not become a zero TX budget.
        let caps = PeerInitCaps::from_init_body(Some(0x09), Some(0));
        assert_eq!(caps.batch_size, 65535, "wire 0 = unset, not a 0 budget");
    }
}

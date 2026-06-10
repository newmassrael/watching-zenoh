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
//! The `transport-batching` gate inside `from_init_body` (whether to honor
//! the peer-advertised `batch_size` or clamp to the full MTU) moves here
//! with the decoder, so `wz-session-core` now owns a `transport-batching`
//! gate-only feature; `wz-runtime-tokio`'s same-named feature forwards to
//! it so the negotiation semantics stay consistent across the workspace.
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
/// on the wire: no feature-gate honoring — [`PeerInitCaps::from_init_body`]
/// layers the `transport-batching` projection on top, and
/// [`init_ack_exceeds_advertisement`] validates against the unprojected
/// values (the wire-conformance rule is feature-independent).
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
/// [`decode_wire_caps`]), not the `transport-batching`-honored projection
/// `PeerInitCaps::from_init_body` stores: wire conformance is
/// feature-independent, and the cfg-off projection clamps the peer field
/// to 65535, which would falsify exactly the comparison this predicate
/// exists to make.
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

// ── transport-batching receive-side field-drop NEG ──
//
// `from_init_body` honors the peer-advertised InitSyn `batch_size` only
// when `transport-batching` is ON; with it OFF the peer value is
// discarded and the field is forced to 65535 (full MTU). The ON arm is
// behaviourally covered by wz-runtime-tokio's
// `r121d_peer_init_caps_decodes_packed_sn_res_byte` (which asserts the
// honored 1024 under `cfg(feature = "transport-batching")`, and runs in
// Layer C1's workspace test because the runtime crate's defaults enable
// the feature). The OFF arm had no behavioural test — Layer C1h subset
// #1/#7 only `cargo build`s the gate, proving it compiles, not that the
// peer value is dropped. This NEG pins it: with the feature off, the
// same `Some(1024)` peer advertisement must NOT survive into
// `batch_size`, while the packed `sn_res` byte (feature-independent)
// still decodes. The gate selects the OFF arm; it runs in the isolated
// `cargo test -p wz-session-core` lanes (C1c/d/e), whose feature set
// leaves transport-batching off (the workspace build unifies it ON from
// the runtime crate, where the POS arm above runs instead).
#[cfg(test)]
#[cfg(not(feature = "transport-batching"))]
mod tests {
    use super::*;

    #[test]
    fn peer_batch_size_discarded_when_transport_batching_off() {
        // sn_res 0x09 = seq 1 | (req 2 << 2); peer advertises batch 1024.
        let caps = PeerInitCaps::from_init_body(Some(0x09), Some(1024));
        assert_eq!(caps.seq_num_res, 1, "packed sn_res still decodes");
        assert_eq!(caps.req_id_res, 2, "packed sn_res still decodes");
        assert_eq!(
            caps.batch_size, 65535,
            "peer-advertised batch_size must be discarded (clamped to full \
             MTU) when transport-batching is off"
        );
    }
}

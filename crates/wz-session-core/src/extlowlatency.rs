// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the Z_EXT_LOWLATENCY establishment extension wire shape
//! (`transport-lowlatency`).
//!
//! zenoh advertises the lowlatency transport as a zero-length UNIT extension
//! on the Init and Open transport messages: `pub type LowLatency =
//! zextunit!(0x5, false)` at BOTH
//! `commons/zenoh-protocol/src/transport/init.rs:162` and `open.rs:128` — ext
//! id `0x5`, the `ExtUnit` encoding (no payload — presence IS the signal), and
//! NO mandatory (`_Z_MSG_EXT_FLAG_M` = `0x10`) bit, so a peer that does not
//! support lowlatency drops the extension silently rather than rejecting the
//! handshake. The capability is negotiated by AND of both sides:
//! `io/zenoh-transport/src/unicast/establishment/ext/lowlatency.rs:78` —
//! `state.is_lowlatency &= other_ext.is_some()` — and is FINALIZED at the
//! InitSyn -> InitAck exchange (zenoh `send_open_syn` / `recv_open_ack` carry
//! nothing). When both peers signal it, the transport drops the Frame(sn)
//! wrapper, the sequence-number machinery, and fragmentation, serializing the
//! bare NetworkMessage directly (`commons/zenoh-codec/src/transport/mod.rs`
//! `TransportMessageLowLatencyRef`).
//!
//! This module is the codec LAYER only — the `(0x5, ENC_UNIT, empty body)`
//! envelope on Init / Open, plus the presence projector the establishment
//! demux (`crate::drive::dispatch_link_event`) feeds the inbound ext chain
//! into. The runtime per-session `is_lowlatency` state, the offer staging into
//! the role ext chains, the `&=` merge, and the lean tx / rx data path live in
//! [`crate::session_actions`] / [`crate::drive`]. It mirrors the
//! [`crate::extauth`] precedent (a distinct establishment ext on the same
//! Init / Open carrier) but is its own SSOT because lowlatency is a distinct
//! concern in a distinct ext id slot (zenoh establishment id space: 0x1 QoS,
//! 0x2 Shm, 0x3 Auth, 0x4 MultiLink, 0x5 LowLatency, 0x6 Compression,
//! 0x7 Patch) and carries a UNIT body (no value), not the ExtZbuf the auth ext
//! carries.
//!
//! QoS exclusivity: zenoh forbids `is_qos && is_lowlatency`
//! (`io/zenoh-transport/src/unicast/manager.rs:264`). wz has no transport-QoS
//! establishment extension (its `qos` module is per-message Priority /
//! CongestionControl metadata, a data-plane concern — not zenoh's transport
//! `is_qos`), so the exclusivity is vacuously satisfied here. If a transport-QoS
//! ext lands later, the guard belongs at the offer-injection point, not in this
//! codec.

use wz_codecs::ext_entry::ExtEntryOwned;

use crate::unit_ext::{chain_has_ext_eid, encode_unit_ext};

/// Z_EXT_LOWLATENCY ext id on the Init / Open establishment messages — zenoh
/// `init.rs:162` / `open.rs:128` `zextunit!(0x5, false)`. The establishment
/// messages have their own ext id space (0x1 QoS, 0x2 Shm, 0x3 Auth,
/// 0x4 MultiLink, 0x5 LowLatency, 0x6 Compression, 0x7 Patch).
pub const LOWLATENCY_EXT_ID: u8 = crate::ext_header::establishment_ext_id::LOWLATENCY;

/// Build the Z_EXT_LOWLATENCY `ExtEntry`: the unit (zero-length) marker that
/// advertises lowlatency capability (the [`crate::unit_ext`] mechanism at the
/// lowlatency id). zenoh `zextunit!(0x5, false)`; the surrounding
/// [`crate::ext_chain::encode_ext_chain`] applies the chain-continuation `Z` bit.
pub fn encode_lowlatency_ext() -> ExtEntryOwned {
    encode_unit_ext(LOWLATENCY_EXT_ID)
}

/// Project the peer's lowlatency capability from an establishment ext chain:
/// `true` iff the chain carries the Z_EXT_LOWLATENCY id. The merge side
/// (`SessionLinkActions::negotiate_lowlatency_against_peer`) ANDs this against the
/// local offer, reproducing zenoh `is_lowlatency &= other_ext.is_some()`.
pub fn peer_offered_lowlatency(extensions: &[ExtEntryOwned]) -> bool {
    chain_has_ext_eid(extensions, LOWLATENCY_EXT_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the on-the-wire header byte (`0x05` = UNIT encoding | id 0x05, no
    /// M, Z patched by the chain codec) — the shape zenoh emits for
    /// `init::ext::LowLatency` / `open::ext::LowLatency`.
    #[test]
    fn lowlatency_ext_header_is_unit_id_five() {
        let ext = encode_lowlatency_ext();
        assert_eq!(
            ext.header, 0x05,
            "UNIT enc (0x00) | LOWLATENCY_EXT_ID (0x05)"
        );
        assert_eq!(ext.ext_id(), LOWLATENCY_EXT_ID);
    }

    /// The encoded entry is exactly ONE byte (the header) — a unit ext carries
    /// no length-prefixed body, the defining property of `zextunit!`.
    #[test]
    fn lowlatency_ext_encodes_to_a_single_byte() {
        let ext = encode_lowlatency_ext();
        assert_eq!(ext.as_borrowed().encode_to_vec().len(), 1);
    }

    /// A chain carrying the lowlatency ext projects to `true`; the offer / merge
    /// path reads exactly this.
    #[test]
    fn peer_offer_detected_in_a_chain() {
        assert!(peer_offered_lowlatency(&[encode_lowlatency_ext()]));
    }

    /// An empty chain, or one carrying only a FOREIGN establishment ext (e.g. a
    /// 0x06 Compression-shaped unit entry), projects to `false` — the lowlatency
    /// id is not confused with a neighbour in the id space.
    #[test]
    fn peer_offer_absent_without_the_ext() {
        assert!(!peer_offered_lowlatency(&[]));
        // A foreign establishment ext (a 0x06 Compression-shaped unit entry).
        assert!(!peer_offered_lowlatency(&[encode_unit_ext(0x06)]));
    }
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the Z_EXT_QOS establishment extension wire shape (`transport-qos`).
//!
//! zenoh negotiates the QoS transport (per-(priority,reliability) SN conduits)
//! via ext id `0x1` on the Init transport message, in ONE of two mutually
//! exclusive forms (`commons/zenoh-protocol/src/transport/init.rs:146-147`):
//!   - `pub type QoS = zextunit!(0x1, false)` — the presence-only UNIT form a
//!     peer with QoS enabled but NO per-link priority/reliability metadata sends;
//!   - `pub type QoSLink = zextz64!(0x1, false)` — the z64 form a peer with
//!     `#priorities=` / `#reliability=` endpoint metadata sends (the packed
//!     priority-range + reliability), NEVER alongside the unit.
//! Both mean `is_qos = true`; only the absence of BOTH is `NoQoS`
//! (`io/zenoh-transport/src/unicast/establishment/ext/qos.rs`
//! `try_from_exts`). The capability is negotiated by AND of both sides — if
//! EITHER peer is `NoQoS` the result is `NoQoS` (the `else { NoQoS }` arm in
//! `recv_init_syn` / `recv_init_ack`).
//!
//! wz EMITS the presence-only UNIT form (`0x1`, ENC_UNIT, no body — byte-
//! identical to what a default `qos`-on zenohd sends). wz DECODE tolerates BOTH:
//! [`peer_offered_qos`] matches ext id `0x1` regardless of the encoding nibble
//! (`ext_id() = header & 0x0F` masks ENC_Z64 `0x20` and the M bit off), so a
//! priority-configured zenohd advertising `QoSLink` is correctly read as
//! `is_qos = true` and its z64 body is length-skipped by the generic
//! `crate::ext_chain::decode_ext_chain` (no Init ext-chain desync). The
//! `QoSLink` PRIORITY-RANGE semantics (the per-link `select` config) are
//! deferred to the wz<->zenohd priority-range interop follow-on (S4); here
//! `is_qos` decides only "per-priority conduits: `Priority::NUM` vs 1".
//!
//! This module is the codec LAYER only — the `(0x1, ENC_UNIT, empty body)`
//! envelope on Init, plus the presence projector the establishment demux
//! (`crate::drive::dispatch_link_event`) feeds the inbound ext chain into. The
//! per-session `is_qos` state, the offer staging into the Init role ext chains,
//! the `&=` merge, and the QoS conduit / Frame `ext_qos` data path live in
//! [`crate::session_actions`] / [`crate::drive`]. It mirrors the
//! [`crate::extlowlatency`] precedent (a distinct establishment ext on the same
//! Init carrier, its own SSOT because QoS is a distinct id-`0x1` slot).
//!
//! QoS exclusivity: zenoh forbids `is_qos && is_lowlatency`
//! (`io/zenoh-transport/src/unicast/manager.rs:264`
//! `bail!("'qos' and 'lowlatency' options are incompatible")`). The guard lives
//! at the offer-injection point (`SessionLinkActions::set_qos_offer` refuses the
//! QoS offer when a lowlatency offer is already staged), NOT in this codec.

use wz_codecs::ext_entry::ExtEntryOwned;

use crate::unit_ext::{chain_has_ext_eid, encode_unit_ext};

/// Z_EXT_QOS ext id on the Init establishment message — zenoh
/// `init.rs:146-147` `zextunit!(0x1, false)` (unit) XOR `zextz64!(0x1, false)`
/// (link). The establishment messages have their own ext id space (0x1 QoS,
/// 0x2 Shm, 0x3 Auth, 0x4 MultiLink, 0x5 LowLatency, 0x6 Compression,
/// 0x7 Patch).
pub const QOS_EXT_ID: u8 = 0x01;

/// Build the Z_EXT_QOS `ExtEntry`: the presence-only UNIT marker wz advertises
/// (the [`crate::unit_ext`] mechanism at the QoS id). zenoh
/// `State::QoS { priorities: None, reliability: None } -> Some(QoS::new())` =
/// `zextunit!(0x1)`; the surrounding [`crate::ext_chain::encode_ext_chain`]
/// applies the chain-continuation `Z` bit. wz never emits `QoSLink` (the z64
/// priority-range form) — it carries no per-link endpoint metadata yet (S4).
pub fn encode_qos_ext() -> ExtEntryOwned {
    encode_unit_ext(QOS_EXT_ID)
}

/// Project the peer's QoS capability from an establishment ext chain: `true`
/// iff the chain carries EITHER `zextunit!(0x1)` (header `0x01`) or
/// `zextz64!(0x1)` (`QoSLink`, header `0x21`). The merge side
/// (`SessionLinkActions::negotiate_qos_against_peer`) ANDs this against the local
/// offer, reproducing zenoh's "both sides QoS or NoQoS" (`is_qos &= peer_offered`).
///
/// R311y505 — the two forms are now named EXPLICITLY. They used to be accepted as
/// a side effect of matching on the 4-bit id field alone, which is a different
/// claim: it accepts anything at id 0x1 in any encoding, present or future. Here
/// the acceptance is deliberate and bounded, because zenoh's QoS genuinely IS a
/// dual ext whose two forms both mean "this peer does QoS"
/// (`transport/init.rs:147-148`, unit XOR z64 with superset/subset containment).
///
/// That reasoning does NOT generalise, which is why the loose match had to go:
/// zenoh's `Shm` at id 0x2 is a ZBuf CHALLENGE, not a second spelling of a
/// capability marker, and reading it as one made wz negotiate SHM with a peer
/// that had issued a challenge wz cannot answer (measured against a real
/// `zenohd --features shared-memory`).
pub fn peer_offered_qos(extensions: &[ExtEntryOwned]) -> bool {
    chain_has_ext_eid(extensions, QOS_EXT_ID)
        || chain_has_ext_eid(extensions, QOS_EXT_ID | crate::ext_header::EXT_ENC_Z64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit_ext::encode_unit_ext;
    use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
    use wz_codecs::ext_zint::ExtZint;

    /// Locks the on-the-wire header byte (`0x01` = UNIT encoding | id 0x01, no
    /// M, Z patched by the chain codec) — the shape zenoh emits for the
    /// presence-only `init::ext::QoS`.
    #[test]
    fn qos_ext_header_is_unit_id_one() {
        let ext = encode_qos_ext();
        assert_eq!(ext.header, 0x01, "UNIT enc (0x00) | QOS_EXT_ID (0x01)");
        assert_eq!(ext.ext_id(), QOS_EXT_ID);
    }

    /// The encoded entry is exactly ONE byte (the header) — the presence-only
    /// unit ext carries no body, the defining property of `zextunit!`.
    #[test]
    fn qos_ext_encodes_to_a_single_byte() {
        assert_eq!(encode_qos_ext().as_borrowed().encode_to_vec().len(), 1);
    }

    /// A chain carrying the unit QoS ext projects to `true`.
    #[test]
    fn peer_offer_detected_for_the_unit_form() {
        assert!(peer_offered_qos(&[encode_qos_ext()]));
    }

    /// RANK-2 faithfulness: a priority-configured zenohd sends `QoSLink` (a z64
    /// at id 0x1, header `0x21` = id 0x1 | ENC_Z64 0x20), NOT the unit.
    /// `peer_offered_qos` must STILL read it as QoS (else wz mis-negotiates
    /// NoQoS against a QoS peer). The z64 body's range meaning is deferred (S4);
    /// only the presence at id 0x1 matters here.
    #[test]
    fn peer_offer_detected_for_the_z64_qoslink_form() {
        let qos_link = ExtEntryOwned {
            header: 0x21, // id 0x1 | ENC_Z64 (0x20)
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint::default()),
        };
        assert_eq!(qos_link.ext_id(), QOS_EXT_ID, "the low nibble is the id");
        assert!(
            peer_offered_qos(&[qos_link]),
            "QoSLink (z64) at id 0x1 is is_qos=true, same as the unit form"
        );
    }

    /// An empty chain, or one carrying only a FOREIGN establishment ext (a 0x05
    /// LowLatency-shaped unit entry), projects to `false` — QoS is not confused
    /// with a neighbour in the id space.
    #[test]
    fn peer_offer_absent_without_the_ext() {
        assert!(!peer_offered_qos(&[]));
        assert!(!peer_offered_qos(&[encode_unit_ext(0x05)]));
    }
}

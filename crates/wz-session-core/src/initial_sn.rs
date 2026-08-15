// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The OpenSyn / OpenAck `initial_sn` DERIVATION — zenoh's `compute_sn`.
//!
//! Every wz host built its `SessionInitParams` with a literal
//! `initial_sn: 0` (`wz-ap-demo/src/args.rs`, `wz-capi-core/src/drive.rs`,
//! `wz-replay/src/live.rs`, `wz-mcu-session-acceptor/src/lib.rs`), so every
//! session wz has ever opened announced the SAME ring origin. Neither
//! upstream ships a constant:
//!
//! - **zenoh 1.5.0** derives it —
//!   `compute_sn(mine_zid, other_zid, resolution)`, a `Shake128` XOF over the
//!   two zids masked to the negotiated FrameSN ring
//!   (`io/zenoh-transport/src/unicast/establishment/mod.rs:104-118`), called
//!   at BOTH Open seams: `open.rs:440` builds the OpenSyn, `accept.rs:646`
//!   the OpenAck.
//! - **zenoh-pico** draws it from entropy —
//!   `z_random_fill(&param->_initial_sn_tx, ..)` masked by
//!   `_z_sn_modulo_mask` (`src/transport/unicast/transport.c:157-160`).
//!
//! wz takes ZENOH's derivation rather than pico's draw, and the reason is a
//! property wz needs and pico's random does not have. zenoh states it in the
//! function's own comment: *"In case of multilink it's important that the
//! same initial_sn is used for every connection attempt. Instead of storing
//! the state everywhere, we make sure that we always compute the same
//! initial_sn."* wz HAS multilink (`wz-runtime-tokio/src/multilink.rs`) and a
//! redial supervisor (`reconnect.rs`), so a re-attempt of the same
//! `(own zid, peer zid)` pair must land on the same origin without anybody
//! persisting it — which is exactly what a pure function of the two zids
//! gives and a fresh random draw destroys. It also makes the seam idempotent:
//! re-encoding an OpenSyn cannot move the ring origin out from under a TX
//! counter already seeded from it.
//!
//! The second reason is profile reach. `getrandom` is deliberately NOT a
//! `wz-session-core` dependency (see the `hmac` / `sha2` block in
//! `Cargo.toml`: the OS-entropy constructor stays AP-only), so a
//! pico-shaped random draw would be an AP-only derivation with the MCU
//! acceptor left on the literal `0` — a fallback indistinguishable from the
//! defect it replaces. A hash of two values both roles already hold reaches
//! every profile identically.
//!
//! ## Why byte-identity with zenoh is worth having even though nothing checks it
//!
//! `initial_sn` is ANNOUNCED, never recomputed: the peer reads the value out
//! of the Open body and seeds its RX gate with it
//! (`SessionLinkActions::handle_inbound_consuming`'s Open arms), so no
//! implementation on the far side ever re-derives ours. A cheaper hash would
//! therefore be unobservable to a peer. It is not unobservable to wz's own
//! passive plane, which reads FOREIGN sessions: `Shake128` over the zid pair
//! is a predicate a dissector can CHECK against a real zenoh peer's announced
//! origin, and that only exists if wz spells the derivation the same way.
//! Hence the transcription rather than a reuse of the already-linked `sha2`.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

/// The Open-body `initial_sn` for a session between `own_zid` and
/// `peer_zid`, projected onto the ring of `sn_mask`
/// ([`crate::sn::mask_from_res`] over the NEGOTIATED `seq_num_res`).
///
/// Transcribes zenoh's `compute_sn`: absorb `own_zid` then `peer_zid` as
/// wire bytes, squeeze, read little-endian, mask. The argument ORDER is the
/// correctness term — zenoh passes `(mine, other)` at both seams, so the two
/// ends of one session derive DIFFERENT origins for their own TX rings, and
/// swapping them would make an initiator announce the origin its acceptor is
/// about to announce back.
///
/// The zid slices are the WIRE bytes, which is what zenoh hashes:
/// `hasher.update(&zid.to_le_bytes()[..zid.size()])` absorbs exactly the
/// bytes its codec writes (`zenoh-codec/src/core/zenohid.rs:37`), and
/// [`crate::session_init_params::SessionInitParams::zid`] holds that same
/// 1..=16-byte wire form.
///
/// ## Eight bytes squeezed, not four
///
/// zenoh reads `(0 as TransportSn).to_le_bytes()` — four bytes, because its
/// `TransportSn` is a `u32` (`zenoh-protocol/src/transport/mod.rs:99`) and
/// its widest ring is capped there. wz's SN is a real `u64`, so a four-byte
/// read would leave the top half of a `seq_num_res == 3` ring unreachable.
/// Reading EIGHT bytes and masking is a strict extension, not a divergence:
/// an XOF is a byte stream and little-endian puts the first bytes in the low
/// positions, so for every resolution zenoh can express the masked value is
/// bit-identical to what zenoh computes. `the_low_half_is_what_zenoh_reads`
/// pins that.
pub fn derive_initial_sn(own_zid: &[u8], peer_zid: &[u8], sn_mask: u64) -> u64 {
    let mut hasher = Shake128::default();
    hasher.update(own_zid);
    hasher.update(peer_zid);
    let mut bytes = 0u64.to_le_bytes();
    hasher.finalize_xof().read(&mut bytes);
    u64::from_le_bytes(bytes) & sn_mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sn::mask_from_res;

    const A: &[u8] = &[0x01, 0x02, 0x03, 0x04];
    const B: &[u8] = &[0x0a, 0x0b, 0x0c, 0x0d];

    /// The whole point of the round: the value is no longer the literal `0`
    /// every wz host announced. Asserted on the SHIPPED demo zid against a
    /// real peer zid, so a derivation that silently produced 0 for the
    /// deployed inputs would still fail here.
    #[test]
    fn the_shipped_demo_zid_no_longer_announces_zero() {
        assert_ne!(derive_initial_sn(A, B, mask_from_res(2)), 0);
    }

    /// zenoh's stated reason for a HASH rather than a draw: every connection
    /// attempt for one `(own, peer)` pair recomputes the same origin with
    /// nothing stored. This is what lets the encode seam re-seed the TX
    /// counter idempotently.
    #[test]
    fn the_same_pair_derives_the_same_origin_every_time() {
        let first = derive_initial_sn(A, B, mask_from_res(2));
        let second = derive_initial_sn(A, B, mask_from_res(2));
        assert_eq!(first, second);
    }

    /// The argument order is a correctness term, not a style choice: the two
    /// ends of ONE session must not derive the same origin, or an acceptor
    /// would announce back exactly what its initiator just announced.
    #[test]
    fn the_two_ends_of_one_session_derive_different_origins() {
        let initiator = derive_initial_sn(A, B, mask_from_res(2));
        let acceptor = derive_initial_sn(B, A, mask_from_res(2));
        assert_ne!(
            initiator, acceptor,
            "compute_sn(mine, other) is not symmetric"
        );
    }

    /// A different peer moves the origin — the property a constant `0`
    /// destroyed, and the one a same-node/two-peer test can see.
    #[test]
    fn a_different_peer_moves_the_origin() {
        let to_b = derive_initial_sn(A, B, mask_from_res(2));
        let to_c = derive_initial_sn(A, &[0x0a, 0x0b, 0x0c, 0x0e], mask_from_res(2));
        assert_ne!(to_b, to_c);
    }

    /// The absorbed bytes are a CONCATENATION with no separator, exactly as
    /// zenoh writes it — so this records the aliasing that follows from
    /// transcribing upstream rather than pretending it does not exist:
    /// `(AB, C)` and `(A, BC)` hash to the same origin. Harmless here (a zid
    /// pair is not attacker-chosen on both sides and the value is announced,
    /// not authenticated), and DIVERGING to a length-prefixed absorb would
    /// break the byte-identity this module exists for.
    #[test]
    fn the_absorb_is_unseparated_concatenation_like_upstream() {
        let split_left = derive_initial_sn(&[0x01, 0x02], &[0x03], mask_from_res(3));
        let split_right = derive_initial_sn(&[0x01], &[0x02, 0x03], mask_from_res(3));
        assert_eq!(split_left, split_right);
    }

    /// Every resolution projects onto its own ring — `mask_from_res` is the
    /// same SSOT the TX mint and the RX gate walk, so an origin off the ring
    /// would make the first announced SN unreachable by the counter.
    #[test]
    fn every_resolution_lands_on_its_own_ring() {
        for res in 0u8..=3 {
            let mask = mask_from_res(res);
            let sn = derive_initial_sn(A, B, mask);
            assert_eq!(sn & mask, sn, "res {res} origin is off its ring");
        }
    }

    /// The eight-byte squeeze is REACHED, not merely written. Added because
    /// the probe that truncates `derive_initial_sn` back to zenoh's four
    /// bytes left every other test in this module GREEN — `mask_from_res(3)`
    /// is 63 bits wide but nothing asserted a value ever landed above the
    /// `u32` ceiling, so the widening had no witness. Scanning a fixed
    /// sixteen-pair grid keeps the assertion deterministic while making the
    /// four-byte read structurally unable to satisfy it.
    #[test]
    fn the_widest_ring_reaches_past_the_u32_ceiling() {
        let reached = (0u8..16).any(|i| {
            derive_initial_sn(
                &[0x01, 0x02, 0x03, i],
                &[0x0a, 0x0b, 0x0c, i],
                mask_from_res(3),
            ) > u32::MAX as u64
        });
        assert!(
            reached,
            "a 63-bit ring must be reachable above 2^32, or the squeeze is truncated"
        );
    }

    /// The eight-byte squeeze is a strict EXTENSION of zenoh's four-byte one:
    /// for the widest ring zenoh can express (`TransportSn` is a `u32`), the
    /// wz value equals `u32::from_le_bytes` over the first four squeezed
    /// bytes — the same number zenoh's `compute_sn` returns.
    #[test]
    fn the_low_half_is_what_zenoh_reads() {
        let mut hasher = Shake128::default();
        hasher.update(A);
        hasher.update(B);
        let mut four = [0u8; 4];
        hasher.finalize_xof().read(&mut four);
        let zenoh_value = u32::from_le_bytes(four) as u64;

        // res 2 masks to 28 bits, so compare on the full u32 ring the way
        // zenoh's own `RES_U64` cap does.
        assert_eq!(derive_initial_sn(A, B, u32::MAX as u64), zenoh_value);
    }
}

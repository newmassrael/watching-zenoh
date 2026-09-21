// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//!
//! ## Why the sponge is spelled here rather than taken from `sha3`
//!
//! R2776 — for its STACK, measured on the Cortex-M0 acceptor, whose 16 KB of
//! SRAM holds `.bss` and the stack together. `sha3::Shake128` wraps the
//! Keccak state in a block buffer and hands `finalize_xof` a reader that owns
//! another copy of both, so this one call took a 1192-byte frame, and the
//! permutation's own 368 on top of it, to hash at most 32 bytes into 8. It
//! sat on the deepest path the acceptor has (the OpenAck emit, inside the
//! receive callback), which is where open-debt item 805 found that
//! acceptor's stack overflowing into `.bss`.
//!
//! The function is unchanged: SHAKE128 as FIPS 202 defines it, over the SAME
//! permutation `sha3` calls (`keccak::f1600`), absorbed at SHAKE128's rate,
//! padded with its `0x1F .. 0x80` domain bits, squeezed from the first
//! lane. What is gone is the buffering, not the construction, and
//! `shake128_is_the_reference_shake128` keeps it that way by comparing it
//! with `sha3::Shake128` — the crate zenoh's `compute_sn` uses — across
//! every length pair the wire allows and past the rate.

/// SHAKE128's rate in bytes: 1600 state bits minus twice the 128-bit
/// capacity, FIPS 202 §6.2.
const SHAKE128_RATE: usize = 168;

/// SHAKE128 as a bare sponge over `keccak::f1600`, reading the first eight
/// output bytes — all this module squeezes.
struct Shake128 {
    state: [u64; 25],
    /// Bytes absorbed into the current block.
    pos: usize,
}

impl Shake128 {
    fn new() -> Self {
        Self {
            state: [0; 25],
            pos: 0,
        }
    }

    /// XOR one byte into the state at byte offset `at`, little-endian within
    /// its lane — the byte order FIPS 202 fixes for the state.
    fn xor_byte(&mut self, at: usize, byte: u8) {
        self.state[at / 8] ^= u64::from(byte) << (8 * (at % 8));
    }

    fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            self.xor_byte(self.pos, byte);
            self.pos += 1;
            if self.pos == SHAKE128_RATE {
                keccak::f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    /// Pad and squeeze eight bytes. SHAKE's domain suffix `1111` and the
    /// first bit of `pad10*1` share the byte after the message (`0x1F`); the
    /// last bit of the pad closes the block (`0x80`). Eight bytes are within
    /// one rate, so one permutation serves the whole squeeze.
    fn squeeze_u64(mut self) -> [u8; 8] {
        self.xor_byte(self.pos, 0x1F);
        self.xor_byte(SHAKE128_RATE - 1, 0x80);
        keccak::f1600(&mut self.state);
        self.state[0].to_le_bytes()
    }
}

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
    let mut hasher = Shake128::new();
    hasher.absorb(own_zid);
    hasher.absorb(peer_zid);
    u64::from_le_bytes(hasher.squeeze_u64()) & sn_mask
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
        let mut four = [0u8; 4];
        reference_shake128(A, B, &mut four);
        let zenoh_value = u32::from_le_bytes(four) as u64;

        // res 2 masks to 28 bits, so compare on the full u32 ring the way
        // zenoh's own `RES_U64` cap does.
        assert_eq!(derive_initial_sn(A, B, u32::MAX as u64), zenoh_value);
    }

    /// The XOF zenoh's `compute_sn` calls, from the crate it calls it from.
    fn reference_shake128(first: &[u8], second: &[u8], out: &mut [u8]) {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut hasher = sha3::Shake128::default();
        hasher.update(first);
        hasher.update(second);
        hasher.finalize_xof().read(out);
    }

    /// R2776 — the sponge written here IS SHAKE128, checked against the
    /// reference over the whole space the wire can hand it and past it.
    ///
    /// A zid is 1..=16 wire bytes, so every pair of lengths in 0..=16 is
    /// covered, each with content that differs per position so a byte
    /// dropped, doubled or misplaced within a lane changes the answer.
    /// Lengths that reach and cross the 168-byte rate are covered as well,
    /// because the block boundary is the one branch no zid pair can reach,
    /// and a sponge that only ever absorbs one block would pass everything
    /// else. The last arm feeds exactly one rate of input, which is where the
    /// padding lands at offset 0 of a fresh block.
    ///
    /// The inputs are slices of two fixed buffers rather than vectors: this
    /// module is compiled by the no-alloc Open-body build too, and its tests
    /// run there (a Layer C count guard selects them with `alloc` off).
    #[test]
    fn shake128_is_the_reference_shake128() {
        /// The longest input any arm below feeds.
        const LONGEST: usize = 336;
        let pattern = |seed: u8| -> [u8; LONGEST] {
            core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        };
        let (own_short, peer_short) = (pattern(0x11), pattern(0x5a));
        let (own_long, peer_long) = (pattern(0x23), pattern(0x77));
        let mut compared = 0usize;
        let mut check = |own: &[u8], peer: &[u8]| {
            let mut want = [0u8; 8];
            reference_shake128(own, peer, &mut want);
            assert_eq!(
                derive_initial_sn(own, peer, u64::MAX),
                u64::from_le_bytes(want),
                "SHAKE128 differs from sha3 at lengths ({}, {})",
                own.len(),
                peer.len()
            );
            compared += 1;
        };
        for own_len in 0..=16 {
            for peer_len in 0..=16 {
                check(&own_short[..own_len], &peer_short[..peer_len]);
            }
        }
        for (own_len, peer_len) in [
            (160, 7),
            (167, 0),
            (168, 0),
            (0, 168),
            (100, 100),
            (LONGEST, 1),
        ] {
            check(&own_long[..own_len], &peer_long[..peer_len]);
        }
        assert_eq!(
            compared,
            17 * 17 + 6,
            "ANTI-VACUITY: every length pair must have been compared"
        );
    }
}

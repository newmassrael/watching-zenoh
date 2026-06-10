// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A1a — modular sequence-number arithmetic (zenoh-pico
//! `src/transport/utils.c` mirror).
//!
//! Zenoh transport SNs live on a modular ring whose size is negotiated by
//! the 2-bit `seq_num_res` wire code (INIT/JOIN). Ordering on the ring is
//! the HALF-WINDOW precedence rule — `right` follows `left` iff the modular
//! distance is non-zero and at most half the ring (`_z_sn_precedes`,
//! utils.c:80). This is NOT a plain `<` compare: a peer that batches or
//! skips SNs stays inside the window, while a stale / duplicated datagram
//! falls outside and is dropped (the R311jq review established the same
//! rule on the TX side — frame-scoped minting keeps gaps far below
//! half-window).
//!
//! First consumer: the multicast data plane (session-fsm §2.3 RxDispatch
//! rules applied per-peer, §3.1 `Frame -> per-peer RxDispatch`). UDP
//! multicast reorders and duplicates datagrams, so every inbound Frame is
//! admitted against the announcing peer's last-seen SN before its payload
//! reaches the application registries. Pure no_std + no_alloc;
//! unconditional (like [`crate::reliability`]).

/// Map the 2-bit `seq_num_res` wire code to the SN ring MASK (ring size -
/// 1). Mirrors zenoh-pico `_z_sn_max` / `_z_sn_modulo_mask` (utils.c):
/// `0x00` -> 7-bit, `0x01` -> 14-bit, `0x02` -> 28-bit, `0x03` -> 63-bit
/// (the usable VLE widths of 1/2/4/8-byte encodings). An out-of-range code
/// yields the widest mask — the defensive arm zenoh-pico leaves at 0, but
/// a zero mask would collapse the ring to one value and drop every frame;
/// wz prefers the permissive window (the codec cannot produce a code > 3
/// from the 2-bit field, so the arm is unreachable from the wire).
pub const fn mask_from_res(seq_num_res: u8) -> u64 {
    match seq_num_res {
        0x00 => (u8::MAX >> 1) as u64,
        0x01 => (u16::MAX >> 2) as u64,
        0x02 => (u32::MAX >> 4) as u64,
        _ => u64::MAX >> 1,
    }
}

/// Half the ring (`_z_sn_half`): the largest forward distance still
/// considered "ahead" by [`precedes`].
pub const fn half(mask: u64) -> u64 {
    mask >> 1
}

/// Half-window precedence (`_z_sn_precedes`): does `right` strictly follow
/// `left` on the ring of `mask`? True iff the modular distance
/// `(right - left) & mask` is non-zero and at most [`half`] the ring.
/// Equality is NOT precedence (a duplicate SN is stale).
pub const fn precedes(mask: u64, left: u64, right: u64) -> bool {
    let distance = right.wrapping_sub(left) & mask;
    distance != 0 && distance <= half(mask)
}

/// Modular decrement (`_z_sn_decrement`). Used to seed a peer's last-seen
/// SN from its JOIN-advertised `next_sn` (the next SN it WILL send): the
/// baseline is one before, so the first data frame at exactly `next_sn`
/// passes [`precedes`].
pub const fn decrement(mask: u64, sn: u64) -> u64 {
    sn.wrapping_sub(1) & mask
}

/// Modular increment (`_z_sn_increment`): the TX-side step on the same
/// ring (the multicast TX path mints with this; the unicast chokepoint
/// owns its own monotonic mint).
pub const fn increment(mask: u64, sn: u64) -> u64 {
    sn.wrapping_add(1) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 2-bit wire codes map to the zenoh-pico `_z_sn_max` masks
    /// (utils.c: U8_MAX>>1 / U16_MAX>>2 / U32_MAX>>4 / U64_MAX>>1).
    #[test]
    fn mask_mapping_mirrors_pico() {
        assert_eq!(mask_from_res(0x00), 0x7F);
        assert_eq!(mask_from_res(0x01), 0x3FFF);
        assert_eq!(mask_from_res(0x02), 0x0FFF_FFFF);
        assert_eq!(mask_from_res(0x03), u64::MAX >> 1);
    }

    /// Forward steps within half the ring precede; equality and stale
    /// (backward) SNs do not.
    #[test]
    fn precedes_basic_ordering() {
        let mask = mask_from_res(0x00); // 7-bit ring, half = 63
        assert!(precedes(mask, 0, 1));
        assert!(precedes(mask, 0, 63), "exactly half is still ahead");
        assert!(
            !precedes(mask, 0, 64),
            "past half-window is stale/ambiguous"
        );
        assert!(!precedes(mask, 5, 5), "duplicate SN is not ahead");
        assert!(!precedes(mask, 5, 4), "backward step is stale");
    }

    /// Precedence is modular: wrap-around across the ring boundary stays
    /// within the half-window (the property a plain `<` compare breaks).
    #[test]
    fn precedes_wraps_around_ring() {
        let mask = mask_from_res(0x00); // ring size 128
        assert!(precedes(mask, 127, 0), "127 -> 0 wraps forward");
        assert!(precedes(mask, 120, 10), "distance 18 across the seam");
        assert!(
            !precedes(mask, 0, 127),
            "0 -> 127 is distance 127 = backward"
        );
    }

    /// Seeding a baseline with [`decrement`] admits the very first frame
    /// at the JOIN-advertised `next_sn` (the §3.2 `init_rx_seq` contract).
    #[test]
    fn decrement_seeds_baseline_for_next_sn() {
        let mask = mask_from_res(0x02);
        let next_sn = 42;
        let baseline = decrement(mask, next_sn);
        assert!(precedes(mask, baseline, next_sn));
        // next_sn = 0 wraps the baseline to the ring top and still admits.
        let baseline = decrement(mask, 0);
        assert_eq!(baseline, mask);
        assert!(precedes(mask, baseline, 0));
    }

    /// Increment walks the ring and wraps at the mask (TX mint step).
    #[test]
    fn increment_wraps_at_mask() {
        let mask = mask_from_res(0x01);
        assert_eq!(increment(mask, 0), 1);
        assert_eq!(increment(mask, mask), 0);
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The VLE (`zint`) integer codec both C ABIs serialize with.
//!
//! ## Why it is HERE and not in one of the ABI crates
//!
//! zenoh's `ze_serialize` / `ze_deserialize` family writes a VLE length in front
//! of every variable-width value, and both wz C ABIs export that family —
//! zenoh-pico's `ze_serializer_*` and zenoh-c's, symbol for symbol. The BYTES
//! they must produce are identical, because both are read by the same foreign
//! peers. A second copy of an encoder whose only job is to agree with a wire
//! format is the shape that drifts silently: the copies stay green against their
//! own decoders while diverging from upstream, which is precisely the failure a
//! round-trip test cannot see.
//!
//! So the codec lives in the neutral model crate and both ABIs call it. Nothing
//! here is ABI-shaped — no `z_` name, no `#[no_mangle]`, no result code. The
//! pico ABI's `_z_zint_len` / `_z_zint64_encode_buf` EXPORTS stay in that crate,
//! because an exported C symbol is ABI surface even when its body is one line.
//!
//! ## The ninth byte is asymmetric, and that is the whole subtlety
//!
//! pico expresses the length as a mask ladder (`VLE_LEN<n>_MASK` is
//! `UINT64_MAX << (7 * n)`, so "fits in n bytes" is "no bits above 7n are set")
//! and the last rung is 9, not 10: the ninth byte carries a full 8 bits rather
//! than 7, so 64 bits never need a tenth. A from-scratch `(bits + 6) / 7` gets
//! that wrong, and a decoder that keeps honouring the continuation flag on the
//! ninth byte reads one byte the encoder never wrote.

/// pico's `VLE_LEN` — the maximum VLE encoding length for a `u64`.
pub const VLE_LEN: usize = 9;

/// How many bytes the VLE encoding of `v` occupies (pico `_z_zint_len`,
/// `src/protocol/codec.c:100-130`).
pub fn zint_len(v: u64) -> usize {
    for n in 1..=8u32 {
        if v >> (7 * n) == 0 {
            return n as usize;
        }
    }
    VLE_LEN
}

/// Write the VLE encoding of `v` into `out`, returning the byte count.
///
/// `out` must be at least [`VLE_LEN`] long; every caller in this workspace
/// stacks exactly that.
pub fn encode_zint(out: &mut [u8], v: u64) -> usize {
    let mut lv = v;
    let mut len = 0usize;
    // While bits above the low 7 remain, emit a continuation byte.
    while lv >> 7 != 0 {
        out[len] = ((lv & 0x7f) as u8) | 0x80;
        len += 1;
        lv >>= 7;
    }
    if len != VLE_LEN {
        out[len] = (lv & 0xff) as u8;
        len += 1;
    }
    len
}

/// Read a VLE value from `input`, returning `(value, bytes_consumed)` or `None`
/// when the input ends mid-encoding.
///
/// The ninth byte is terminal REGARDLESS of its high bit — the mirror of
/// [`encode_zint`]'s asymmetry.
pub fn decode_zint(input: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for (i, byte) in input.iter().take(VLE_LEN).enumerate() {
        let is_last = i + 1 == VLE_LEN;
        if is_last {
            value |= u64::from(*byte) << shift;
            return Some((value, i + 1));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encoder and decoder are INVERSES across every rung, including the
    /// ninth-byte asymmetry where a naive decoder reads one byte too many.
    #[test]
    fn zint_round_trips_across_every_rung() {
        let mut probes: Vec<u64> = vec![0, 1, u64::MAX];
        for n in 1..9u32 {
            probes.push((1u64 << (7 * n)) - 1);
            probes.push(1u64 << (7 * n));
        }
        let mut buf = [0u8; VLE_LEN];
        for v in probes {
            let n = encode_zint(&mut buf, v);
            assert_eq!(n, zint_len(v), "encoded length disagrees at {v:#x}");
            let (decoded, used) = decode_zint(&buf[..n]).expect("decodes what it encoded");
            assert_eq!(decoded, v, "round trip failed at {v:#x}");
            assert_eq!(used, n, "decoder consumed a different count at {v:#x}");
        }
    }

    /// A truncated encoding is `None`, not a silently wrong value — the shape a
    /// deserializer needs to report a decode error rather than invent data.
    #[test]
    fn a_truncated_zint_does_not_decode() {
        let mut buf = [0u8; VLE_LEN];
        let n = encode_zint(&mut buf, 1 << 40);
        assert!(n > 1);
        assert!(decode_zint(&buf[..n - 1]).is_none());
        assert!(decode_zint(&[]).is_none());
    }
}

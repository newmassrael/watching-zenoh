// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! INTERNAL pico codec symbols that public example programs link directly.
//!
//! `_z_zint_len` is not part of pico's public API — it lives in
//! `protocol/codec/core.h` behind an underscore — and upstream's `z_pub_thr.c`
//! calls it anyway, to size its payload so the encoded message lands on a round
//! number of bytes. A drop-in that exported only the documented surface would
//! fail to link the canonical throughput benchmark, which is the concrete reason
//! this crate's export policy is "what pico programs CALL", not "what pico
//! documents".
//!
//! Being a pure function of its argument, this one has an unusually strong
//! oracle available: the real `libzenohpico.so` built by
//! `scripts/build-zenoh-pico-cli.sh` exports it, so agreement can be checked
//! against upstream's own compiled code rather than against a table transcribed
//! from its source. `tests/zint_len_against_pico_oracle.rs` does exactly that
//! across every boundary and a swept range.

/// pico `_z_zint_len` (`src/protocol/codec.c:100-130`): how many bytes the VLE
/// encoding of `v` occupies.
///
/// pico expresses this as a mask ladder — `VLE_LEN<n>_MASK` is
/// `UINT64_MAX << (7 * n)`, so "fits in n bytes" is "no bits above 7n are set" —
/// and the last rung is 9, not 10: the ninth byte carries a full 8 bits rather
/// than 7, so 64 bits never need a tenth. That asymmetry is the part a
/// from-scratch `(bits + 6) / 7` would get wrong, and it is why the oracle test
/// sweeps the top of the range rather than sampling it.
#[no_mangle]
pub extern "C" fn _z_zint_len(v: u64) -> u8 {
    for n in 1..=8u32 {
        if v >> (7 * n) == 0 {
            return n as u8;
        }
    }
    9
}

/// pico `_z_zint64_encode_buf` (`src/protocol/codec.c:132-147`): write the VLE
/// encoding of `v` into `buf`, returning the byte count.
///
/// The ninth byte is the asymmetric one and the reason this is not a plain
/// seven-bits-per-byte loop: the continuation loop runs while bits above 7
/// remain, and the FINAL byte is emitted only when fewer than `VLE_LEN` (9)
/// bytes have been written — so a 9-byte encoding carries a full 8 bits in its
/// last byte with no continuation flag, and never spills to a tenth.
///
/// # Safety
/// `buf` must be writable for at least 9 bytes — pico's own callers stack a
/// `uint8_t buf[16]`, and `_z_zint_len` bounds the write at 9.
#[no_mangle]
pub unsafe extern "C" fn _z_zint64_encode_buf(buf: *mut u8, v: u64) -> u8 {
    if buf.is_null() {
        return 0;
    }
    let out = std::slice::from_raw_parts_mut(buf, VLE_LEN);
    encode_zint(out, v) as u8
}

/// pico's `VLE_LEN` — the maximum VLE encoding length for a `u64`.
pub(crate) const VLE_LEN: usize = 9;

/// Write the VLE encoding of `v` into `out`, returning the byte count. The
/// Rust-side helper the serializer uses; `_z_zint64_encode_buf` is its C export.
pub(crate) fn encode_zint(out: &mut [u8], v: u64) -> usize {
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
/// [`encode_zint`]'s asymmetry. A decoder that kept honouring the continuation
/// flag would read a tenth byte that the encoder never writes.
pub(crate) fn decode_zint(input: &[u8]) -> Option<(u64, usize)> {
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
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..2048 {
            probes.push(x);
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
        let mut buf = [0u8; VLE_LEN];
        for v in probes {
            let n = encode_zint(&mut buf, v);
            assert_eq!(
                n as u8,
                _z_zint_len(v),
                "encoded length disagrees with _z_zint_len at {v:#x}"
            );
            let (decoded, used) = decode_zint(&buf[..n]).expect("decodes what it encoded");
            assert_eq!(decoded, v, "round trip failed at {v:#x}");
            assert_eq!(used, n, "decoder consumed a different count at {v:#x}");
        }
    }

    /// A truncated encoding is `None`, not a silently wrong value — the shape a
    /// deserializer needs to report `Z_EDESERIALIZE` rather than invent data.
    #[test]
    fn a_truncated_zint_does_not_decode() {
        let mut buf = [0u8; VLE_LEN];
        let n = encode_zint(&mut buf, 1 << 40);
        assert!(n > 1);
        assert!(decode_zint(&buf[..n - 1]).is_none());
        assert!(decode_zint(&[]).is_none());
    }

    /// Every boundary in the mask ladder, stated as the two values that
    /// straddle it. The ORACLE test proves agreement with upstream; this one
    /// keeps the shape readable and fails fast without a built pico.
    #[test]
    fn zint_len_boundaries() {
        assert_eq!(_z_zint_len(0), 1);
        assert_eq!(_z_zint_len(127), 1);
        assert_eq!(_z_zint_len(128), 2);
        assert_eq!(_z_zint_len((1 << 14) - 1), 2);
        assert_eq!(_z_zint_len(1 << 14), 3);
        assert_eq!(_z_zint_len((1 << 56) - 1), 8);
        // The ninth byte carries 8 bits, not 7 — so 2^56 through u64::MAX all
        // cost 9, and there is no tenth rung.
        assert_eq!(_z_zint_len(1 << 56), 9);
        assert_eq!(_z_zint_len(u64::MAX), 9);
    }
}

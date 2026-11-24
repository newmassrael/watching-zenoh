// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The VLE (`zint`) integer codec zenoh's serialization format writes, which both C ABIs export.
//!
//! ## Why it is HERE
//!
//! zenoh's `ze_serialize` / `ze_deserialize` family writes a VLE length in front of every
//! variable-width value, and both wz C ABIs export that family — zenoh-pico's `ze_serializer_*`
//! and zenoh-c's, symbol for symbol. The BYTES they must produce are identical, because both are
//! read by the same foreign peers. A second copy of an encoder whose only job is to agree with a
//! wire format is the shape that drifts silently: the copies stay green against their own decoders
//! while diverging from upstream, which is precisely the failure a round-trip test cannot see.
//!
//! It lived in `wz-capi-core`, the session model both C ABIs share, and moved down here for the
//! reason the encoding id table did (R311y617, [`crate::encoding_ids`]): that crate sits on the
//! tokio engine, and the pico ABI over the cooperative engine
//! (`docs/capi-pico-on-coop-engine.md`) has to reach the codec without it. `wz-capi-core`
//! re-exports this module, so every caller reads the one implementation. Nothing here is
//! ABI-shaped — no `z_` name, no `#[no_mangle]`, no result code. The pico ABI's `_z_zint_len` /
//! `_z_zint64_encode_buf` EXPORTS stay in that crate, because an exported C symbol is ABI surface
//! even when its body is one line.
//!
//! ## The ninth byte is asymmetric, and that is the whole subtlety
//!
//! pico expresses the length as a mask ladder (`VLE_LEN<n>_MASK` is `UINT64_MAX << (7 * n)`, so
//! "fits in n bytes" is "no bits above 7n are set") and the last rung is 9, not 10: the ninth byte
//! carries a full 8 bits rather than 7, so 64 bits never need a tenth. A from-scratch
//! `(bits + 6) / 7` gets that wrong, and a decoder that keeps honouring the continuation flag on
//! the ninth byte reads one byte the encoder never wrote.

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
/// `out` must be at least [`VLE_LEN`] long.
pub fn encode_zint(out: &mut [u8], v: u64) -> usize {
    let mut lv = v;
    let mut len = 0usize;
    loop {
        // The value and the ninth rung end the encoding in ONE condition: a loop that also left
        // on the count alone (or on an index past a nine-byte buffer) has a constant trip count,
        // and the optimizer unrolls it over every rung in each body that holds it.
        let more = (lv > 0x7f) & (len < VLE_LEN - 1);
        // The ninth byte keeps all eight bits and never takes the flag.
        out[len] = (lv as u8) | (u8::from(more) << 7);
        len += 1;
        if !more {
            return len;
        }
        lv >>= 7;
    }
}

/// Read a VLE value from `input`, returning `(value, bytes_consumed)` or `None`
/// when the input ends mid-encoding.
///
/// The ninth byte is terminal REGARDLESS of its high bit — the mirror of
/// [`encode_zint`]'s asymmetry.
pub fn decode_zint(input: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut used = 0usize;
    loop {
        let byte = *input.get(used)?;
        // One exit for the flag and the ninth rung, as in `encode_zint`: a separate count bound
        // is a constant trip count, unrolled over every rung.
        let last = used == VLE_LEN - 1;
        let more = (byte & 0x80 != 0) & !last;
        let bits = if last { byte } else { byte & 0x7f };
        value |= u64::from(bits) << (7 * used);
        used += 1;
        if !more {
            return Some((value, used));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

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

    /// The bytes are pico's, not only a round trip of this encoder: a value
    /// whose low byte has its eighth bit set keeps the seven value bits under
    /// the continuation flag, and the ninth byte carries all eight. Turned red
    /// by a continuation byte that toggles the flag instead of setting it.
    #[test]
    fn zint_writes_the_bytes_pico_writes() {
        let cases: [(u64, &[u8]); 9] = [
            (0, &[0x00]),
            (0x7f, &[0x7f]),
            (0x80, &[0x80, 0x01]),
            (0xff, &[0xff, 0x01]),
            (300, &[0xac, 0x02]),
            (
                (1 << 56) - 1,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
            ),
            (
                1 << 56,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
            ),
            (
                1 << 63,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80],
            ),
            (u64::MAX, &[0xff; VLE_LEN]),
        ];
        for (v, want) in cases {
            let mut buf = [0u8; VLE_LEN];
            let n = encode_zint(&mut buf, v);
            assert_eq!(&buf[..n], want, "the encoding of {v:#x}");
        }
    }

    /// An encoding is written into the first bytes of a buffer longer than it, and the bytes
    /// after it are left as they were: no tenth byte, even when the ninth has its high bit set.
    /// Turned red by an encoder whose ninth rung keeps the continuation flag.
    #[test]
    fn an_encoding_writes_no_byte_past_its_length() {
        for v in [0, 0x7f, 0x80, (1 << 56) - 1, 1 << 56, 1 << 63, u64::MAX] {
            let mut buf = [0xAAu8; VLE_LEN + 1];
            let n = encode_zint(&mut buf, v);
            assert_eq!(n, zint_len(v), "length of {v:#x}");
            assert!(
                buf[n..].iter().all(|&b| b == 0xAA),
                "a byte past the encoding of {v:#x} was written"
            );
        }
    }

    /// The ninth byte ends a decoding whatever its high bit and gives all eight bits, and a
    /// decoding stops at the byte without the flag, leaving what follows unread. Turned red by a
    /// decoder that honours the flag on the ninth byte (it would read a tenth).
    #[test]
    fn a_decoding_ends_at_its_last_byte_and_reads_none_after_it() {
        assert_eq!(decode_zint(&[0xff; VLE_LEN + 1]), Some((u64::MAX, VLE_LEN)));
        let mut top = [0x80u8; VLE_LEN + 1];
        top[VLE_LEN] = 0x01;
        assert_eq!(decode_zint(&top), Some((1 << 63, VLE_LEN)));
        assert_eq!(decode_zint(&[0x00, 0xaa]), Some((0, 1)));
        assert_eq!(decode_zint(&[0x7f, 0xaa]), Some((0x7f, 1)));
        assert_eq!(decode_zint(&[0x80, 0x01, 0xaa]), Some((0x80, 2)));
        assert_eq!(decode_zint(&[0x80]), None);
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

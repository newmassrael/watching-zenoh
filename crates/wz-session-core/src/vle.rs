// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared slice-based VLE (base-128 varint) codec — the borrowed-slice SSOT for
//! both read and write.
//!
//! `sce_forge_runtime::codec::SceCursor::read_vle_u64` is the canonical
//! cursor-driven decoder used wherever a wire message is parsed off a cursor.
//! This module is its borrowed-`&[u8]` twin, for the cases where a VLE field is
//! embedded in an already-buffered `ExtZbuf` body (`source_info_ext`,
//! `declare_ext_keyexpr`, the `extauth_usrpwd` OpenSyn body) rather than read
//! from the live cursor. Factored out so those callers share ONE varint codec
//! instead of each hand-rolling the continuation/over-shift logic (the bug-prone
//! part).
//!
//! WIRE NOTE: [`encode_vle_u64_into`] emits standard LEB128, matching the
//! SCE-generated `ExtZint`/`ExtZbuf` codecs so wz is internally consistent. This
//! DIVERGES from zenoh + zenoh-pico for values `>= 2^63`, which cap the `u64`
//! ZInt at 9 bytes (the 9th byte carries a full 8 data bits) where LEB128 uses
//! 10. The fix belongs in the SCE VLE codegen + `SceCursor` reader (reported
//! upstream); this writer is kept LEB128 to match the SCE-generated path until
//! that lands. Reachable only by full-range `u64` fields (auth nonces, post-2038
//! NTP64); the auth OpenSyn lengths this writer encodes are always `< 2^63`.

/// Read a base-128 VLE-encoded `u64` from the front of `bytes`. Returns
/// `(value, bytes_consumed)` on success; `None` on truncation (the
/// continuation bit is set but the slice ends) or on an over-long encoding
/// whose accumulator would shift past 63 bits (a malformed > `u64` VLE).
pub(crate) fn read_vle_u64(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let chunk = (b & 0x7f) as u64;
        if shift >= 63 && chunk > 1 {
            return None;
        }
        value |= chunk << shift;
        if (b & 0x80) == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

/// Append `v` to `out` as a base-128 LEB128 VLE — the write twin of
/// [`read_vle_u64`] / `SceCursor::read_vle_u64`. The single VLE-u64 writer SSOT
/// (consumed by `source_info_ext`, `response_build`, and the `extauth_usrpwd`
/// OpenSyn body). See the module WIRE NOTE for the `>= 2^63` LEB128-vs-zenoh
/// 9-byte-cap divergence (SCE-codegen-tracked).
pub(crate) fn encode_vle_u64_into(out: &mut alloc::vec::Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7F) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_vle_u64_handles_single_byte_payloads() {
        assert_eq!(read_vle_u64(&[0x00]), Some((0, 1)));
        assert_eq!(read_vle_u64(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn encode_vle_u64_into_round_trips_through_the_reader() {
        // The writer SSOT (consolidated from source_info_ext + extauth_usrpwd's
        // former push_vle) round-trips against read_vle_u64 across the byte-width
        // boundaries. Pins exact bytes for the small values (1-byte: 5; 2-byte:
        // 300 = 0xAC 0x02).
        for v in [0u64, 5, 127, 128, 300, 16_384, u32::MAX as u64, 1 << 62] {
            let mut out = alloc::vec::Vec::new();
            encode_vle_u64_into(&mut out, v);
            assert_eq!(read_vle_u64(&out), Some((v, out.len())), "round-trip {v}");
        }
        let mut five = alloc::vec::Vec::new();
        encode_vle_u64_into(&mut five, 5);
        assert_eq!(five, [0x05]);
        let mut three_hundred = alloc::vec::Vec::new();
        encode_vle_u64_into(&mut three_hundred, 300);
        assert_eq!(three_hundred, [0xAC, 0x02]);
    }

    #[test]
    fn read_vle_u64_handles_multi_byte_payloads() {
        // 0xC8 0x01 = 200 (0xC8 & 0x7F = 0x48, then + 0x01 << 7 = 128 -> 200).
        assert_eq!(read_vle_u64(&[0xC8, 0x01]), Some((200, 2)));
        // 0x81 0x01 = 129 — the multi-byte path past the single-byte 0..=127.
        assert_eq!(read_vle_u64(&[0x81, 0x01]), Some((129, 2)));
    }

    #[test]
    fn read_vle_u64_returns_none_on_truncation() {
        // Continuation bit set but slice ends.
        assert_eq!(read_vle_u64(&[0x80]), None);
        assert!(read_vle_u64(&[]).is_none());
    }

    #[test]
    fn read_vle_u64_returns_none_on_overlong() {
        // 10 continuation bytes then a high chunk would shift past 63 bits.
        let overlong = [0x80u8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        assert_eq!(read_vle_u64(&overlong), None);
    }
}

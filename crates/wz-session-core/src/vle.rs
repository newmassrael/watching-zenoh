// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared slice-based VLE (base-128 varint) decoder — the borrowed-slice SSOT.
//!
//! `sce_forge_runtime::codec::SceCursor::read_vle_u64` is the canonical
//! cursor-driven decoder used wherever a wire message is parsed off a cursor.
//! This module is its borrowed-`&[u8]` twin, for the cases where a VLE field is
//! embedded in an already-buffered `ExtZbuf` body (`source_info_ext`,
//! `declare_ext_keyexpr`) rather than read from the live cursor. Factored out so
//! those callers share ONE slice decoder instead of each hand-rolling the
//! continuation/over-shift logic (the bug-prone part of a varint reader).

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_vle_u64_handles_single_byte_payloads() {
        assert_eq!(read_vle_u64(&[0x00]), Some((0, 1)));
        assert_eq!(read_vle_u64(&[0x7F]), Some((127, 1)));
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

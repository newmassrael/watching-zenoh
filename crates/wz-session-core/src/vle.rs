// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Borrowed-slice / `Vec<u8>` adapter over the `sce_forge_runtime` VLE
//! (base-128 varint) codec — for the cases where a VLE field is embedded in an
//! already-buffered `ExtZbuf` body (`source_info_ext`, `declare_ext_keyexpr`,
//! the `extauth_usrpwd` OpenSyn body) rather than read from / written to a live
//! `SceCursor` / `SceSink`.
//!
//! Both helpers DELEGATE to the `sce_forge_runtime` codec — the ONE VLE SSOT
//! shared with every SCE-generated codec — so wz carries no second varint
//! implementation. The runtime caps a `u64` ZInt at 9 bytes (the 9th byte
//! carries a full 8 data bits, the continuation bit reused as data), byte-
//! identical to canonical zenoh + zenoh-pico (SCE pin >= ba65f7a1b, the VLE
//! 9-byte-cap fix). The former wz-local LEB128 copy and its `>= 2^63`
//! 10-vs-9-byte divergence are retired.

/// Read a base-128 VLE-encoded `u64` from the front of `bytes`. Returns
/// `(value, bytes_consumed)` on success; `None` on truncation / malformed VLE.
/// Delegates to `SceCursor` (the VLE SSOT); a `u64` consumes at most 9 bytes,
/// so a trailing byte is left for the next field, not mis-read.
pub(crate) fn read_vle_u64(bytes: &[u8]) -> Option<(u64, usize)> {
    use sce_forge_runtime::codec::SceCursor;
    let mut cursor = SceCursor::new(bytes);
    let value = cursor.read_vle_u64().ok()?;
    Some((value, bytes.len() - cursor.remaining()))
}

/// Append `v` to `out` as a VLE — the write twin of [`read_vle_u64`]. Delegates
/// to the `sce_forge_runtime` sink codec (the VLE SSOT): a `u64` caps at 9 bytes
/// per canonical zenoh/pico. Consumed by `source_info_ext`, `response_build`,
/// and the `extauth_usrpwd` OpenSyn body.
pub(crate) fn encode_vle_u64_into(out: &mut alloc::vec::Vec<u8>, v: u64) {
    use sce_forge_runtime::codec::{SceSink, VecSink};
    VecSink::new(out)
        .write_vle_u64(v)
        .expect("VecSink is growable, so write_vle_u64 never overflows");
}

/// Write one zenoh `ZBuf` — a VLE length then that many bytes — to `out` (the
/// `Zenoh080` length-prefixed-bytes framing). The SSOT for the "one ZBuf"
/// primitive every Z_EXT_AUTH method body is built from: usrpwd's
/// `{user, hmac}` is two of these, pubkey's RSA-key `{n, e}` + ciphertext are
/// three. `pub` so the AP-only pubkey method (in `wz-runtime-tokio`) consumes
/// the same definition as no_std usrpwd — one framing, two crates, zero drift.
pub fn write_zbuf(out: &mut alloc::vec::Vec<u8>, bytes: &[u8]) {
    encode_vle_u64_into(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Read one zenoh `ZBuf` (VLE length + that many bytes) from `cursor`, the read
/// twin of [`write_zbuf`]. `None` on truncation / malformed VLE / a length that
/// overruns the buffer. The cursor advances past the bytes so successive ZBufs
/// in one body read in sequence (usrpwd's two, pubkey's three).
pub fn read_zbuf(
    cursor: &mut sce_forge_runtime::codec::SceCursor<'_>,
) -> Option<alloc::vec::Vec<u8>> {
    let len = cursor.read_vle_u64().ok()? as usize;
    let slice = cursor.peek_slice(len).ok()?.to_vec();
    cursor.advance(len).ok()?;
    Some(slice)
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
        // The writer SSOT (delegating to the sce_forge_runtime VLE codec)
        // round-trips against read_vle_u64 across the byte-width boundaries,
        // INCLUDING the full-range u64::MAX (>= 2^63, the 9-byte cap). Pins exact
        // bytes for the small values (1-byte: 5; 2-byte: 300 = 0xAC 0x02).
        for v in [
            0u64,
            5,
            127,
            128,
            300,
            16_384,
            u32::MAX as u64,
            1 << 62,
            u64::MAX,
        ] {
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
    fn zbuf_round_trips_through_the_cursor() {
        use sce_forge_runtime::codec::SceCursor;
        // Two successive ZBufs in one body read back in sequence with the right
        // boundary (the usrpwd {user, hmac} / pubkey {n, e} shape). The second
        // length deliberately crosses the single-byte VLE boundary (300).
        let mut out = alloc::vec::Vec::new();
        write_zbuf(&mut out, b"alice");
        write_zbuf(&mut out, &[0xAB; 300]);
        let mut cursor = SceCursor::new(&out);
        assert_eq!(read_zbuf(&mut cursor).as_deref(), Some(&b"alice"[..]));
        assert_eq!(read_zbuf(&mut cursor).as_deref(), Some(&[0xAB; 300][..]));
        assert_eq!(cursor.remaining(), 0, "both ZBufs consumed exactly");
        // A truncated length-prefixed blob (claims 5 bytes, has 2) reads None.
        let truncated = alloc::vec![0x05u8, 0x01, 0x02];
        let mut t = SceCursor::new(&truncated);
        assert_eq!(read_zbuf(&mut t), None);
    }

    #[test]
    fn read_vle_u64_reads_the_canonical_9_byte_cap() {
        // Canonical zenoh/pico u64: 9 bytes, the 9th carrying a full 8 data bits
        // (continuation bit reused as data). u64::MAX = 0xFF x9 -> exactly 9
        // consumed; a trailing byte is left for the next field, not mis-read as
        // a 10th VLE byte (the LEB128 10-byte form the old wz reader expected is
        // retired with the SCE 9-byte-cap delegation).
        assert_eq!(read_vle_u64(&[0xFFu8; 9]), Some((u64::MAX, 9)));
        let mut with_tail = alloc::vec::Vec::from([0xFFu8; 9]);
        with_tail.push(0xAB);
        assert_eq!(read_vle_u64(&with_tail), Some((u64::MAX, 9)));
    }
}

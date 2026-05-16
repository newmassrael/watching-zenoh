// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `fragment` codec (§4.2 transport
//! Fragment body, VLE sn + tail payload).
//!
//! Validates the VLE u64 encoder's wire-byte agreement across the
//! continuation-byte boundary, which is the most pervasive primitive
//! across the §3-§7 codec set: VLE u64 carries sn, lease,
//! initial_sn, batch_size, cookie_len, payload_len, num_locators,
//! request_id, key_id, and ~10 other length / sequence fields.
//! Validating VLE here implicitly raises confidence in every
//! downstream codec that consumes the same primitive.
//!
//! Wire shape (per `vendor/zenoh-pico/src/protocol/codec/transport.c:
//! 408-434`): `VLE(sn) + (optional first/drop ext, gated on header.Z)
//! + payload bytes`. With `header = 0` (no Z flag, no first/drop
//! extension emission), the body reduces to `VLE(sn) + payload`,
//! which is the exact same shape `wz_codecs::fragment::Fragment::encode()`
//! emits from the wz `fragment.scxml` declaration.
//!
//! Corpus picks VLE width boundaries (1-byte form covers sn 0..=127;
//! 2-byte form starts at sn=128; 3-byte form starts at sn=16384) plus
//! representative payloads (empty / single byte / multi-byte) to
//! exercise the post-VLE tail emission path.

use wz_codecs::fragment::Fragment;
use zenoh_pico_sys::{
    _z_delete_context_t, _z_fragment_encode, _z_slice_t, _z_t_msg_fragment_t, _z_wbuf_clear,
    _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

/// Encode a Fragment body via zenoh-pico FFI with the simplest header
/// (no Z flag, no first/drop extensions). The body reduces to
/// `VLE(sn) + payload` — the canonical wire shape this Layer 3 test
/// exists to validate.
fn zenoh_pico_encode_fragment(sn: u64, payload: &[u8]) -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(1024, false);

        // For empty payloads, leave start NULL so `_z_slice_check`
        // returns false and the encoder skips the `_z_wbuf_write_bytes`
        // call entirely. This matches the wz path's behavior on
        // `payload: vec![]` (no bytes appended after the VLE sn).
        let (start, len) = if payload.is_empty() {
            (std::ptr::null::<u8>(), 0usize)
        } else {
            (payload.as_ptr(), payload.len())
        };

        let slice = _z_slice_t {
            len,
            start,
            // Non-owning view; zero-initialized delete context means
            // _z_slice_check returns true iff start != NULL, and no
            // deleter is invoked on cleanup (we own the Rust-side
            // backing buffer and drop it after the encoder returns).
            _delete_context: _z_delete_context_t {
                deleter: None,
                context: std::ptr::null_mut(),
            },
        };

        // _z_zint_t is `size_t` on the C side (`usize` after
        // bindgen). On 64-bit hosts this is u64-equivalent; on 32-bit
        // hosts the caller is responsible for keeping sn < usize::MAX
        // (which `Fragment.sn: u64` doesn't enforce — a future
        // documentation pass on the wire-spec subset should record
        // the 32-bit deploy-class invariant explicitly).
        let msg = _z_t_msg_fragment_t {
            _payload: slice,
            _sn: sn as usize,
            first: false,
            drop: false,
        };

        let ret = _z_fragment_encode(&mut wbf, 0u8, &msg);
        assert_eq!(
            ret, 0,
            "_z_fragment_encode returned non-zero for sn={sn} \
             payload.len={}",
            payload.len()
        );

        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();

        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_fragment_vle_width_boundaries() {
    // VLE u64 width boundaries (per RFC §5.B Appendix B base-128
    // continuation chain):
    //   1-byte form:  0..=127           (top bit 0 in the only byte)
    //   2-byte form:  128..=16383       (top bit 1 in byte 0)
    //   3-byte form:  16384..=2097151
    //
    // Payloads sample 0/1/multi-byte tails so the post-VLE
    // write_bytes path is exercised in all three width regimes.
    let corpus: Vec<(u64, Vec<u8>)> = vec![
        // 1-byte VLE width
        (0, vec![]),
        (1, vec![0xCA, 0xFE]),
        (127, vec![0xAA, 0xBB, 0xCC]),
        // 2-byte VLE width boundary
        (128, vec![0xDE, 0xAD]),
        (256, vec![0xBE, 0xEF, 0x11, 0x22]),
        (16383, vec![]),
        // 3-byte VLE width boundary
        (16384, vec![0x77]),
        (1_000_000, vec![0x01, 0x02, 0x03, 0x04, 0x05]),
        // High-magnitude — exercises the 4-byte+ VLE form
        (u32::MAX as u64, vec![0xFF]),
    ];

    for (sn, payload) in corpus {
        let wz_bytes = Fragment {
            sn,
            payload: payload.clone(),
        }
        .encode();
        let pico_bytes = zenoh_pico_encode_fragment(sn, &payload);
        assert_eq!(
            wz_bytes, pico_bytes,
            "Layer 3 byte mismatch for fragment(sn={sn}, payload={payload:?}): \
             wz={wz_bytes:?}, zenoh-pico={pico_bytes:?}"
        );
    }
}

#[test]
fn layer3_fragment_empty_payload_yields_vle_only() {
    // Pin the empty-payload contract: body reduces to VLE(sn) bytes
    // alone — no trailing padding, no length sentinel.
    let wz = Fragment {
        sn: 0,
        payload: vec![],
    }
    .encode();
    let pico = zenoh_pico_encode_fragment(0, &[]);
    assert_eq!(wz, pico);
    assert_eq!(wz, vec![0x00], "empty Fragment with sn=0 → [0x00]");
}

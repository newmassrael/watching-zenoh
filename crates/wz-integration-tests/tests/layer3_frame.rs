// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `frame` codec (§4.2 transport Frame
//! body, VLE sn + tail payload).
//!
//! Wire shape (per `vendor/zenoh-pico/src/protocol/codec/transport.c:
//! 386-395`): `VLE(sn) + payload bytes`. With `header = 0` (no Z
//! flag), `_z_frame_encode` writes `_z_zsize_encode(wbf, msg->_sn)`
//! followed by `_z_wbuf_write_bytes(wbf, _z_zbuf_get_rptr(msg->_payload),
//! 0, _z_zbuf_len(msg->_payload))`. The body reduces to
//! `VLE(sn) + payload`, identical to the `fragment` codec's wire
//! shape — only the enclosing transport MID differs (T_FRAME 0x05
//! vs T_FRAGMENT 0x06), which is written by the transport-envelope
//! encoder, not by the body codec.
//!
//! The structural difference from `layer3_fragment.rs`: frame's
//! `_z_t_msg_frame_t._payload` is `*mut _z_zbuf_t` (NOT `_z_slice_t`
//! by value). We construct the zbuf via `_z_slice_as_zbuf` from a
//! Rust-backed slice; for empty payload we pass `_payload = null`
//! since `_z_frame_encode` short-circuits on the null check
//! (`if (msg->_payload != NULL)`).

use wz_codecs::frame::Frame;
use zenoh_pico_sys::{
    _z_delete_context_t, _z_frame_encode, _z_slice_as_zbuf, _z_slice_t, _z_t_msg_frame_t,
    _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear, _z_zbuf_t,
};

fn zenoh_pico_encode_frame(sn: u64, payload: &[u8]) -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(1024, false);

        // Empty payload: pass _payload=null so the encoder skips the
        // write_bytes call (`if (msg->_payload != NULL)` short-
        // circuit). Non-empty: wrap the Rust slice via
        // _z_slice_as_zbuf into MaybeUninit-backed storage so the
        // lint doesn't flag a default-init-then-overwrite pattern.
        let mut zbuf_storage: std::mem::MaybeUninit<_z_zbuf_t> = std::mem::MaybeUninit::uninit();
        let payload_ptr: *mut _z_zbuf_t = if payload.is_empty() {
            std::ptr::null_mut()
        } else {
            let slice = _z_slice_t {
                len: payload.len(),
                start: payload.as_ptr(),
                _delete_context: _z_delete_context_t {
                    deleter: None,
                    context: std::ptr::null_mut(),
                },
            };
            zbuf_storage.write(_z_slice_as_zbuf(slice));
            zbuf_storage.as_mut_ptr()
        };

        let msg = _z_t_msg_frame_t {
            _payload: payload_ptr,
            _sn: sn as usize,
        };

        let ret = _z_frame_encode(&mut wbf, 0u8, &msg);
        assert_eq!(
            ret, 0,
            "_z_frame_encode returned non-zero for sn={sn} \
             payload.len={}",
            payload.len()
        );

        let mut zbf_out = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf_out._ios._buf, zbf_out._ios._w_pos).to_vec();

        _z_zbuf_clear(&mut zbf_out);
        _z_wbuf_clear(&mut wbf);
        // The zbuf wrapping the Rust slice (`zbuf_storage`) holds a
        // non-owning view; dropping it does not free the Rust-side
        // backing buffer (which goes out of scope normally).
        bytes
    }
}

#[test]
fn layer3_frame_vle_width_boundaries() {
    // Same VLE corpus as fragment but encoded via the frame path.
    // Frame and fragment share the wire-body shape but route through
    // different msg structs (zbuf-pointer vs slice-by-value); the
    // bytes-on-wire MUST match either way.
    let corpus: Vec<(u64, Vec<u8>)> = vec![
        (0, vec![]),
        (1, vec![0xCA, 0xFE]),
        (127, vec![0xAA, 0xBB, 0xCC]),
        (128, vec![0xDE, 0xAD]),
        (256, vec![0xBE, 0xEF, 0x11, 0x22]),
        (16383, vec![]),
        (16384, vec![0x77]),
        (1_000_000, vec![0x01, 0x02, 0x03, 0x04, 0x05]),
        (u32::MAX as u64, vec![0xFF]),
    ];

    for (sn, payload) in corpus {
        let wz_bytes = Frame {
            sn,
            payload: payload.clone(),
        }
        .encode_to_vec();
        let pico_bytes = zenoh_pico_encode_frame(sn, &payload);
        assert_eq!(
            wz_bytes, pico_bytes,
            "Layer 3 byte mismatch for frame(sn={sn}, payload={payload:?}): \
             wz={wz_bytes:?}, zenoh-pico={pico_bytes:?}"
        );
    }
}

#[test]
fn layer3_frame_matches_fragment_when_no_extension() {
    // Cross-codec invariant: with header=0 (no Z flag, no
    // first/drop), Frame and Fragment encode the SAME wire bytes
    // for the SAME (sn, payload) input. The on-wire distinction
    // comes from the enclosing transport-envelope MID (T_FRAME 0x05
    // vs T_FRAGMENT 0x06), which is written by the transport-message
    // encoder, not by the body codecs themselves.
    let sn = 42u64;
    let payload = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let frame_bytes = Frame {
        sn,
        payload: payload.clone(),
    }
    .encode_to_vec();
    let fragment_bytes = wz_codecs::fragment::Fragment {
        sn,
        payload: payload.clone(),
    }
    .encode_to_vec();
    assert_eq!(
        frame_bytes, fragment_bytes,
        "wz Frame and Fragment must emit identical body bytes \
         for the same (sn, payload) input"
    );
    // Zenoh-pico path should also match.
    let pico_frame = zenoh_pico_encode_frame(sn, &payload);
    assert_eq!(frame_bytes, pico_frame, "wz Frame == zenoh-pico Frame");
}

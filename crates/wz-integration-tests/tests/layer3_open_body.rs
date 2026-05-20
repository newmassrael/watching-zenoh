// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `open_body` codec.
//!
//! Validates the B5-λ NEGATION present-if gate (`!parent.A`). Open
//! body is the FIRST codec where a parent header flag negation
//! controls field emission: the cookie pair is present when
//! parent.A=0 (Open SYN), absent when parent.A=1 (Open ACK).
//!
//! Wire shape (per vendor/zenoh-pico/src/protocol/codec/transport.c:288-305):
//!   - VLE(lease)
//!   - VLE(initial_sn)
//!   - !parent.A: VLE(cookie_len) + cookie bytes
//!
//! parent_flags carries the per-message header byte's R/M/A/Z bits;
//! Open uses bit 5 = _Z_FLAG_T_OPEN_A = 0x20.

use wz_codecs::open_body::OpenBody;
use zenoh_pico_sys::{
    _z_delete_context_t, _z_open_encode, _z_slice_t, _z_t_msg_open_t, _z_wbuf_clear, _z_wbuf_make,
    _z_wbuf_to_zbuf, _z_zbuf_clear,
};

const FLAG_OPEN_A: u8 = 0x20;

fn make_slice(payload: &[u8]) -> _z_slice_t {
    if payload.is_empty() {
        _z_slice_t {
            len: 0,
            start: std::ptr::null(),
            _delete_context: _z_delete_context_t {
                deleter: None,
                context: std::ptr::null_mut(),
            },
        }
    } else {
        _z_slice_t {
            len: payload.len(),
            start: payload.as_ptr(),
            _delete_context: _z_delete_context_t {
                deleter: None,
                context: std::ptr::null_mut(),
            },
        }
    }
}

fn zenoh_pico_encode_open(parent_flags: u8, lease: u64, initial_sn: u64, cookie: &[u8]) -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(256, false);
        let msg = _z_t_msg_open_t {
            _lease: lease as usize,
            _initial_sn: initial_sn as usize,
            _cookie: make_slice(cookie),
        };
        let ret = _z_open_encode(&mut wbf, parent_flags, &msg);
        assert_eq!(ret, 0, "_z_open_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_open_body_syn_cookie_present() {
    // parent.A=0 → cookie emitted (VLE len + bytes).
    let parent_flags = 0u8;
    let lease = 120u64;
    let initial_sn = 42u64;
    let cookie = vec![0xCA, 0xFE, 0xBA, 0xBE];

    let wz_bytes = OpenBody {
        lease,
        initial_sn,
        cookie_len: Some(cookie.len() as u64),
        cookie: Some(cookie.clone()),
    }
    .encode_to_vec(((parent_flags) >> 5) & 1);

    let pico_bytes = zenoh_pico_encode_open(parent_flags, lease, initial_sn, &cookie);
    assert_eq!(wz_bytes, pico_bytes);
}

#[test]
fn layer3_open_body_ack_no_cookie() {
    // parent.A=1 → cookie pair absent. Body = VLE(lease) + VLE(initial_sn) only.
    let parent_flags = FLAG_OPEN_A;
    let lease = 120u64;
    let initial_sn = 42u64;

    let wz_bytes = OpenBody {
        lease,
        initial_sn,
        cookie_len: None,
        cookie: None,
    }
    .encode_to_vec(((parent_flags) >> 5) & 1);

    let pico_bytes = zenoh_pico_encode_open(parent_flags, lease, initial_sn, &[]);
    assert_eq!(wz_bytes, pico_bytes);
}

#[test]
fn layer3_open_body_vle_boundaries() {
    // Exercise VLE width boundaries for lease + initial_sn under
    // both A=0 and A=1.
    let corpus: Vec<(u64, u64)> = vec![
        (0, 0),
        (127, 127),
        (128, 256),
        (16383, 16384),
        (1_000_000, u32::MAX as u64),
    ];
    for (lease, initial_sn) in corpus {
        // A=1 (no cookie)
        let wz_a1 = OpenBody {
            lease,
            initial_sn,
            cookie_len: None,
            cookie: None,
        }
        .encode_to_vec(((FLAG_OPEN_A) >> 5) & 1);
        let pico_a1 = zenoh_pico_encode_open(FLAG_OPEN_A, lease, initial_sn, &[]);
        assert_eq!(wz_a1, pico_a1, "A=1 lease={lease} sn={initial_sn}");

        // A=0 with a small cookie
        let cookie = vec![0x11, 0x22];
        let wz_a0 = OpenBody {
            lease,
            initial_sn,
            cookie_len: Some(cookie.len() as u64),
            cookie: Some(cookie.clone()),
        }
        .encode_to_vec(0);
        let pico_a0 = zenoh_pico_encode_open(0, lease, initial_sn, &cookie);
        assert_eq!(wz_a0, pico_a0, "A=0 lease={lease} sn={initial_sn}");
    }
}

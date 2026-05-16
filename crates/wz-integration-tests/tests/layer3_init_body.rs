// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `init_body` codec.
//!
//! Validates two-flag parent-header gating: parent.S (size negotiation
//! sn_res + batch_size) and parent.A (cookie carrier). Both gates use
//! "set means present" — the positive form (no negation). Init also
//! exercises the cbyte multi-bit pack (whatami 2-bit + zid_len_m1
//! 4-bit) which is the same primitive class as scout's cbyte but a
//! distinct layout.
//!
//! Wire shape (per vendor/zenoh-pico/src/protocol/codec/transport.c:182-219):
//!   - byte 0: version
//!   - byte 1: cbyte (low 2 bits = whatami wire-form; high 4 bits = zid_len_m1)
//!   - bytes 2+: zid (length = zid_len_m1 + 1)
//!   - parent.S: sn_res byte (low 2 bits = seq_num_res, bits 2..3 = req_id_res)
//!               + batch_size u16 BE
//!   - parent.A: VLE(cookie_len) + cookie bytes

use wz_codecs::init_body::InitBody;
use zenoh_pico_sys::{
    _z_delete_context_t, _z_id_t, _z_init_encode, _z_slice_t, _z_t_msg_init_t, _z_wbuf_clear,
    _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear, z_whatami_t,
};

const FLAG_INIT_S: u8 = 0x40;
const FLAG_INIT_A: u8 = 0x20;

// API enum values from include/zenoh-pico/api/constants.h.
const WHATAMI_ROUTER: z_whatami_t = 0x01;
#[allow(dead_code)]
const WHATAMI_PEER: z_whatami_t = 0x02;
#[allow(dead_code)]
const WHATAMI_CLIENT: z_whatami_t = 0x04;

/// Mirror zenoh-pico's `_z_whatami_to_uint8` (codec/transport.c:31-37):
/// `(whatami >> 1) & 0x03`. Returns the 2-bit wire-form encoding.
fn whatami_wire_form(api_whatami: z_whatami_t) -> u8 {
    ((api_whatami >> 1) & 0x03) as u8
}

fn pack_zid(payload: &[u8]) -> [u8; 16] {
    assert!(payload.len() <= 16);
    let mut id = [0u8; 16];
    id[..payload.len()].copy_from_slice(payload);
    id
}

/// Pre-compute the cbyte that zenoh-pico's init encoder will produce
/// (transport.c:189-192): low 2 bits = wire-form whatami,
/// high 4 bits = zid_len - 1.
fn compute_init_cbyte(api_whatami: z_whatami_t, zid_len: u8) -> u8 {
    assert!(zid_len >= 1 && zid_len <= 16, "init body requires zid_len in 1..=16");
    whatami_wire_form(api_whatami) | (((zid_len - 1) & 0x0F) << 4)
}

/// Mirror the sn_res / req_id_res packing zenoh-pico does at
/// transport.c:196-197: `(seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)`.
fn pack_sn_res(seq_num_res: u8, req_id_res: u8) -> u8 {
    (seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)
}

fn make_cookie_slice(payload: &[u8]) -> _z_slice_t {
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

struct InitInput<'a> {
    version: u8,
    whatami: z_whatami_t,
    zid: &'a [u8],
    seq_num_res: u8,
    req_id_res: u8,
    batch_size: u16,
    cookie: &'a [u8],
    parent_flags: u8,
}

fn zenoh_pico_encode_init(input: &InitInput) -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(256, false);
        let msg = _z_t_msg_init_t {
            _zid: _z_id_t {
                id: pack_zid(input.zid),
            },
            _cookie: make_cookie_slice(input.cookie),
            _batch_size: input.batch_size,
            _whatami: input.whatami,
            _req_id_res: input.req_id_res,
            _seq_num_res: input.seq_num_res,
            _version: input.version,
            _patch: 0,
        };
        let ret = _z_init_encode(&mut wbf, input.parent_flags, &msg);
        assert_eq!(ret, 0, "_z_init_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_init_body_s0_a0() {
    // No optional fields: body = version + cbyte + zid only.
    let input = InitInput {
        version: 0x05,
        whatami: WHATAMI_ROUTER,
        zid: &[0x01, 0x02, 0x03],
        seq_num_res: 0,
        req_id_res: 0,
        batch_size: 0,
        cookie: &[],
        parent_flags: 0,
    };
    let cbyte = compute_init_cbyte(input.whatami, input.zid.len() as u8);
    let wz = InitBody {
        version: input.version,
        cbyte,
        zid: input.zid.to_vec(),
        sn_res: None,
        batch_size: None,
        cookie_len: None,
        cookie: None,
    }
    .encode(input.parent_flags);
    let pico = zenoh_pico_encode_init(&input);
    assert_eq!(wz, pico);
}

#[test]
fn layer3_init_body_s1_a0() {
    // parent.S=1 only: + sn_res + batch_size.
    let input = InitInput {
        version: 0x05,
        whatami: WHATAMI_PEER,
        zid: &[0x10, 0x20, 0x30, 0x40],
        seq_num_res: 0x03, // 2-bit max
        req_id_res: 0x02,
        batch_size: 0xCAFE,
        cookie: &[],
        parent_flags: FLAG_INIT_S,
    };
    let cbyte = compute_init_cbyte(input.whatami, input.zid.len() as u8);
    let sn_res = pack_sn_res(input.seq_num_res, input.req_id_res);
    let wz = InitBody {
        version: input.version,
        cbyte,
        zid: input.zid.to_vec(),
        sn_res: Some(sn_res),
        batch_size: Some(input.batch_size),
        cookie_len: None,
        cookie: None,
    }
    .encode(input.parent_flags);
    let pico = zenoh_pico_encode_init(&input);
    assert_eq!(wz, pico);
}

#[test]
fn layer3_init_body_s0_a1() {
    // parent.A=1 only: + cookie.
    let cookie = vec![0xBA, 0xBE, 0x11, 0x22];
    let input = InitInput {
        version: 0x05,
        whatami: WHATAMI_CLIENT,
        zid: &[0xAA, 0xBB],
        seq_num_res: 0,
        req_id_res: 0,
        batch_size: 0,
        cookie: &cookie,
        parent_flags: FLAG_INIT_A,
    };
    let cbyte = compute_init_cbyte(input.whatami, input.zid.len() as u8);
    let wz = InitBody {
        version: input.version,
        cbyte,
        zid: input.zid.to_vec(),
        sn_res: None,
        batch_size: None,
        cookie_len: Some(cookie.len() as u64),
        cookie: Some(cookie.clone()),
    }
    .encode(input.parent_flags);
    let pico = zenoh_pico_encode_init(&input);
    assert_eq!(wz, pico);
}

#[test]
fn layer3_init_body_s1_a1() {
    // Both gates set: full body shape.
    let cookie = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x77];
    let input = InitInput {
        version: 0x05,
        whatami: WHATAMI_ROUTER,
        zid: &(0x01..=0x10).collect::<Vec<u8>>(), // 16-byte zid
        seq_num_res: 0x01,
        req_id_res: 0x03,
        batch_size: 0xFFFF,
        cookie: &cookie,
        parent_flags: FLAG_INIT_S | FLAG_INIT_A,
    };
    let cbyte = compute_init_cbyte(input.whatami, input.zid.len() as u8);
    let sn_res = pack_sn_res(input.seq_num_res, input.req_id_res);
    let wz = InitBody {
        version: input.version,
        cbyte,
        zid: input.zid.to_vec(),
        sn_res: Some(sn_res),
        batch_size: Some(input.batch_size),
        cookie_len: Some(cookie.len() as u64),
        cookie: Some(cookie.clone()),
    }
    .encode(input.parent_flags);
    let pico = zenoh_pico_encode_init(&input);
    assert_eq!(wz, pico);
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `join` codec (multicast handshake).
//!
//! Validates parent.S gating + multi-VLE next_sn chain. Uses
//! plain-mode next_sn (single reliable/best_effort pair) — the QoS
//! mode that splits into 8 per-priority pairs is a separate codec
//! variant that lands in a later round when QoS becomes part of the
//! Layer 3 catalog.
//!
//! Wire shape (per vendor/zenoh-pico/src/protocol/codec/transport.c:40-102):
//!   - byte 0: version
//!   - byte 1: cbyte (low 2 bits = whatami wire-form; high 4 = zid_len_m1)
//!   - bytes 2+: zid
//!   - parent.S: sn_res byte + batch_size u16 LE
//!   - always: VLE(lease) + VLE(next_sn_reliable) + VLE(next_sn_best_effort)
//!
//! The init_body LE fix (R44) applies to join's batch_size too —
//! both inherit the zenoh-pico `_z_uint16_encode` LSB-first
//! convention.

use wz_codecs::join::Join;
use zenoh_pico_sys::{
    _z_conduit_sn_list_t, _z_conduit_sn_list_t__bindgen_ty_1, _z_coundit_sn_t, _z_id_t,
    _z_join_encode, _z_t_msg_join_t, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
    z_whatami_t,
};

const FLAG_JOIN_S: u8 = 0x40;
const WHATAMI_PEER: z_whatami_t = 0x02;

fn whatami_wire_form(api: z_whatami_t) -> u8 {
    ((api >> 1) & 0x03) as u8
}

fn pack_zid(payload: &[u8]) -> [u8; 16] {
    assert!(payload.len() <= 16);
    let mut id = [0u8; 16];
    id[..payload.len()].copy_from_slice(payload);
    id
}

fn compute_join_cbyte(api_whatami: z_whatami_t, zid_len: u8) -> u8 {
    assert!((1..=16).contains(&zid_len));
    whatami_wire_form(api_whatami) | (((zid_len - 1) & 0x0F) << 4)
}

fn pack_sn_res(seq_num_res: u8, req_id_res: u8) -> u8 {
    (seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)
}

struct JoinInput<'a> {
    version: u8,
    whatami: z_whatami_t,
    zid: &'a [u8],
    seq_num_res: u8,
    req_id_res: u8,
    batch_size: u16,
    lease: u64,
    next_sn_reliable: u64,
    next_sn_best_effort: u64,
    parent_flags: u8,
}

fn zenoh_pico_encode_join(input: &JoinInput) -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(256, false);
        let next_sn = _z_conduit_sn_list_t {
            _val: _z_conduit_sn_list_t__bindgen_ty_1 {
                _plain: _z_coundit_sn_t {
                    _reliable: input.next_sn_reliable as usize,
                    _best_effort: input.next_sn_best_effort as usize,
                },
            },
            _is_qos: false,
        };
        let msg = _z_t_msg_join_t {
            _zid: _z_id_t {
                id: pack_zid(input.zid),
            },
            _lease: input.lease as usize,
            _next_sn: next_sn,
            _batch_size: input.batch_size,
            _whatami: input.whatami,
            _req_id_res: input.req_id_res,
            _seq_num_res: input.seq_num_res,
            _version: input.version,
            _patch: 0,
        };
        let ret = _z_join_encode(&mut wbf, input.parent_flags, &msg);
        assert_eq!(ret, 0, "_z_join_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_join_s0_basic() {
    let input = JoinInput {
        version: 0x05,
        whatami: WHATAMI_PEER,
        zid: &[0x01, 0x02, 0x03],
        seq_num_res: 0,
        req_id_res: 0,
        batch_size: 0,
        lease: 10_000,
        next_sn_reliable: 42,
        next_sn_best_effort: 99,
        parent_flags: 0,
    };
    let cbyte = compute_join_cbyte(input.whatami, input.zid.len() as u8);
    let wz = Join {
        version: input.version,
        cbyte,
        zid: input.zid.to_vec(),
        sn_res: None,
        batch_size: None,
        lease: input.lease,
        next_sn_reliable: input.next_sn_reliable,
        next_sn_best_effort: input.next_sn_best_effort,
    }
    .encode(input.parent_flags);
    let pico = zenoh_pico_encode_join(&input);
    assert_eq!(wz, pico);
}

#[test]
fn layer3_join_s1_with_size_negotiation() {
    let input = JoinInput {
        version: 0x05,
        whatami: WHATAMI_PEER,
        zid: &[0xAA, 0xBB, 0xCC, 0xDD],
        seq_num_res: 0x03,
        req_id_res: 0x02,
        batch_size: 0xCAFE,
        lease: 30_000,
        next_sn_reliable: 1_000,
        next_sn_best_effort: 2_000,
        parent_flags: FLAG_JOIN_S,
    };
    let cbyte = compute_join_cbyte(input.whatami, input.zid.len() as u8);
    let sn_res = pack_sn_res(input.seq_num_res, input.req_id_res);
    let wz = Join {
        version: input.version,
        cbyte,
        zid: input.zid.to_vec(),
        sn_res: Some(sn_res),
        batch_size: Some(input.batch_size),
        lease: input.lease,
        next_sn_reliable: input.next_sn_reliable,
        next_sn_best_effort: input.next_sn_best_effort,
    }
    .encode(input.parent_flags);
    let pico = zenoh_pico_encode_join(&input);
    assert_eq!(wz, pico);
}

#[test]
fn layer3_join_vle_boundaries_on_sn() {
    // Same VLE boundary corpus as fragment/frame, applied to all
    // three VLE fields (lease + next_sn pair). Exercises VLE encoder
    // correctness in the multi-VLE chain context where four VLE
    // fields concatenate without separators on the wire.
    let corpus: Vec<(u64, u64, u64)> = vec![
        (0, 0, 0),
        (127, 127, 127),
        (128, 128, 128),
        (16383, 16384, 1),
        (u32::MAX as u64, 1_000_000, 0),
    ];
    for (lease, sn_r, sn_be) in corpus {
        let input = JoinInput {
            version: 0x05,
            whatami: WHATAMI_PEER,
            zid: &[0x11],
            seq_num_res: 0,
            req_id_res: 0,
            batch_size: 0,
            lease,
            next_sn_reliable: sn_r,
            next_sn_best_effort: sn_be,
            parent_flags: 0,
        };
        let cbyte = compute_join_cbyte(input.whatami, input.zid.len() as u8);
        let wz = Join {
            version: input.version,
            cbyte,
            zid: input.zid.to_vec(),
            sn_res: None,
            batch_size: None,
            lease,
            next_sn_reliable: sn_r,
            next_sn_best_effort: sn_be,
        }
        .encode(input.parent_flags);
        let pico = zenoh_pico_encode_join(&input);
        assert_eq!(
            wz, pico,
            "join VLE chain lease={lease} sn_r={sn_r} sn_be={sn_be}"
        );
    }
}

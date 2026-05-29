// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// Layer 3 wire-interop test — `hello` codec (§3 scouting Hello body).
//
// Validates parent.L gating around the locator list. Two regimes:
//
//   (a) parent.L=0  → locators absent on the wire. Body reduces to
//                      version + cbyte + zid.
//   (b) parent.L=1 with EMPTY locator array  → body = version + cbyte
//       + zid + VLE(0). The encoder writes VLE(num_locators=0) and
//       emits zero per-locator entries.
//
// Non-empty locator construction (parent.L=1 with N>=1 locators)
// requires FFI setup of `_z_locator_t` which embeds `_z_string_t` +
// `_z_str_intmap_t`. That construction needs zenoh-pico's string
// builders (`_z_string_from_str` etc.) bound — deferred to R45b /
// R46. The two regimes covered here are sufficient to prove the
// parent.L gate + zero-locator boundary.
//
// Wire shape (per vendor/zenoh-pico/src/protocol/codec/message.c:646-664):
//   - byte 0: version
//   - byte 1: cbyte (low 2 bits whatami wire-form, high 4 bits zid_len_m1)
//   - bytes 2+: zid
//   - parent.L: VLE(num_locators) + repeat<locator>

use wz_codecs::hello::{Hello, HelloOwned};
use zenoh_pico_sys::{
    _z_hello_encode, _z_id_t, _z_locator_array_t, _z_s_msg_hello_t, _z_wbuf_clear, _z_wbuf_make,
    _z_wbuf_to_zbuf, _z_zbuf_clear, z_whatami_t,
};

const FLAG_HELLO_L: u8 = 0x20;
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

fn compute_hello_cbyte(api_whatami: z_whatami_t, zid_len: u8) -> u8 {
    assert!((1..=16).contains(&zid_len));
    whatami_wire_form(api_whatami) | (((zid_len - 1) & 0x0F) << 4)
}

fn zenoh_pico_encode_hello(
    parent_flags: u8,
    version: u8,
    whatami: z_whatami_t,
    zid: &[u8],
) -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(256, false);
        // Empty locator array: _len=0, _val=null. zenoh-pico's
        // _z_locators_encode writes VLE(0) for this, with no per-
        // locator bytes following.
        let empty_locators = _z_locator_array_t {
            _len: 0,
            _val: std::ptr::null_mut(),
        };
        let msg = _z_s_msg_hello_t {
            _zid: _z_id_t { id: pack_zid(zid) },
            _locators: empty_locators,
            _whatami: whatami,
            _version: version,
        };
        let ret = _z_hello_encode(&mut wbf, parent_flags, &msg);
        assert_eq!(ret, 0, "_z_hello_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_hello_l0_no_locators() {
    // parent.L=0 — locators absent on the wire.
    let version = 0x02u8;
    let whatami = WHATAMI_PEER;
    let zid = vec![0x01, 0x02, 0x03];

    let cbyte = compute_hello_cbyte(whatami, zid.len() as u8);
    let wz = Hello {
        version,
        cbyte,
        zid: &zid,
        num_locators: None,
        locators: None,
    }
    .encode_to_vec(0);

    let pico = zenoh_pico_encode_hello(0u8, version, whatami, &zid);
    assert_eq!(wz, pico);
}

#[test]
fn layer3_hello_l1_empty_locator_array() {
    // parent.L=1 with zero locators — body emits VLE(0) for the count
    // and no per-locator entries.
    let version = 0x02u8;
    let whatami = WHATAMI_PEER;
    let zid = vec![0xAA, 0xBB, 0xCC, 0xDD];

    let cbyte = compute_hello_cbyte(whatami, zid.len() as u8);
    // Owned builder: the empty locator chain is an alloc `Vec` of
    // `LocatorOwned` (vs the borrowed heapless `Vec<_, 64>`); encode via
    // the `try_as_borrowed` projection.
    let wz = HelloOwned {
        version,
        cbyte,
        zid: zid.clone(),
        num_locators: Some(0),
        locators: Some(vec![]),
    }
    .try_as_borrowed()
    .expect("test: empty locator chain")
    .encode_to_vec(((FLAG_HELLO_L) >> 5) & 1);

    let pico = zenoh_pico_encode_hello(FLAG_HELLO_L, version, whatami, &zid);
    assert_eq!(wz, pico);

    // Pin the trailing VLE(0): the last byte should be 0x00.
    assert_eq!(wz.last(), Some(&0x00), "VLE(num_locators=0) trailing byte");
}

#[test]
fn layer3_hello_l0_max_zid() {
    // 16-byte zid + parent.L=0 — exercises the cbyte.zid_len_m1=15
    // boundary together with the L-gate-off branch.
    let version = 0x02u8;
    let whatami = WHATAMI_PEER;
    let zid: Vec<u8> = (0x10..0x20).collect();

    let cbyte = compute_hello_cbyte(whatami, zid.len() as u8);
    let wz = Hello {
        version,
        cbyte,
        zid: &zid,
        num_locators: None,
        locators: None,
    }
    .encode_to_vec(0);

    let pico = zenoh_pico_encode_hello(0u8, version, whatami, &zid);
    assert_eq!(wz, pico);
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop — `ext_envelope` codec (generic TLV ext chain).
//!
//! Validates the wz-side `ExtEnvelope` encoder against zenoh-pico's
//! `_z_msg_ext_encode` (per-entry, src/protocol/codec/ext.c) byte-by-
//! byte. The envelope wire = header_flags byte (parent carrier
//! header) + N entries terminated by Z=0.
//!
//! Per-entry shape (per vendor/zenoh-pico/include/zenoh-pico/protocol/ext.h):
//!   - byte 0: header = (ext_id & 0x0F) | M flag (0x10) | enc<<5 | Z<<7
//!   - body: Unit(empty) / ZInt(VLE u64) / ZBuf(VLE len + bytes)
//!
//! Oracle vector (matches sources/codecs/ext_envelope.scxml line 41-52):
//!   header_flags=0x01, entries=[Unit(id=0,M=0), ZInt(id=1,M=1,val=42),
//!   ZBuf(id=2,M=1,val=[0xAB,0xCD])]
//!   wire = 0x01 0x80 0xB1 0x2A 0x52 0x02 0xAB 0xCD

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::ext_envelope::ExtEnvelope;
use zenoh_pico_sys::{
    _z_msg_ext_encode, _z_msg_ext_make_unit, _z_msg_ext_make_zbuf, _z_msg_ext_make_zint,
    _z_slice_t, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

const ORACLE_WIRE: [u8; 8] = [0x01, 0x80, 0xB1, 0x2A, 0x52, 0x02, 0xAB, 0xCD];

// _z_msg_ext_make_* masks id to _Z_EXT_ID_MASK (low 4 bits = ext_id
// only) and OR-s enc-bits (UNIT=0x00 / ZINT=0x20 / ZBUF=0x40). The M
// flag (0x10) must be post-set on _header for mandatory entries.
const ENTRY0_ID_UNIT: u8 = 0x00; // ext_id=0, M=0
const ENTRY1_ID_ZINT: u8 = 0x01; // ext_id=1; M post-set
const ENTRY2_ID_ZBUF: u8 = 0x02; // ext_id=2; M post-set
const M_FLAG: u8 = 0x10;
const ENTRY1_ZINT_VAL: u64 = 42;
const ENTRY2_ZBUF_VAL: [u8; 2] = [0xAB, 0xCD];

/// Encode the oracle chain via zenoh-pico's per-entry encoder, then
/// prepend the parent header_flags byte to match wz envelope shape.
fn zenoh_pico_encode_oracle_envelope() -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);

        let unit_ext = _z_msg_ext_make_unit(ENTRY0_ID_UNIT);
        let mut zint_ext = _z_msg_ext_make_zint(ENTRY1_ID_ZINT, ENTRY1_ZINT_VAL as usize);
        zint_ext._header |= M_FLAG;
        // ZBuf body is _z_slice_t (non-owning view). Construct a
        // zero-initialized slice and patch the pointer + length —
        // zenoh-pico's encode_zbuf reads (_start, _len) only and
        // does not invoke the delete context for transient encode-
        // side slices.
        let mut zbuf_body: _z_slice_t = std::mem::zeroed();
        zbuf_body.start = ENTRY2_ZBUF_VAL.as_ptr();
        zbuf_body.len = ENTRY2_ZBUF_VAL.len();
        let mut zbuf_ext = _z_msg_ext_make_zbuf(ENTRY2_ID_ZBUF, zbuf_body);
        zbuf_ext._header |= M_FLAG;

        assert_eq!(_z_msg_ext_encode(&mut wbf, &unit_ext, true), 0);
        assert_eq!(_z_msg_ext_encode(&mut wbf, &zint_ext, true), 0);
        assert_eq!(_z_msg_ext_encode(&mut wbf, &zbuf_ext, false), 0);

        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let chain_bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos);
        let mut wire = Vec::with_capacity(1 + chain_bytes.len());
        wire.push(0x01); // header_flags (matches oracle)
        wire.extend_from_slice(chain_bytes);
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        wire
    }
}

#[test]
fn layer3_ext_envelope_oracle_byte_equivalent_to_zenoh_pico() {
    let pico = zenoh_pico_encode_oracle_envelope();
    assert_eq!(
        pico, ORACLE_WIRE,
        "zenoh-pico encode of oracle envelope must match the wz oracle"
    );

    let mut cursor = SceCursor::new(&ORACLE_WIRE);
    let env = ExtEnvelope::decode(&mut cursor).expect("wz decode oracle");
    let wz = env.encode();
    assert_eq!(
        wz, pico,
        "wz ExtEnvelope encode must byte-match zenoh-pico per-entry encode"
    );
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop — R68c inbound ext-chain decode.
//!
//! Reverse-direction counterpart to `layer3_ext_chain_outbound.rs`:
//! zenoh-pico encodes an InitAck wire with the Z flag set and a
//! 3-entry ext chain (Unit / ZInt / ZBuf), wz `parse_inbound`
//! decodes the body AND the trailing ext chain, surfaces the
//! `extensions` field on `InboundFrame::Init`. The per-entry
//! header byte + body discriminant are byte-equivalent to the
//! pico-side values.
//!
//! Wire shape under test:
//!   `[parent_flags|T_MID_INIT, ...init_body, ...ext_chain]`

use sce_forge_runtime::codec::CodecError;
use wz_codecs::ext_entry::ExtEntryOwnedVariant;
use wz_codecs::wire_const::PROTOCOL_VERSION;
use wz_runtime_tokio::session_glue::{
    parse_inbound, InboundFrame, InboundParseError, MAX_EXT_CHAIN_DEPTH,
};
use zenoh_pico_sys::{
    _z_delete_context_t, _z_id_t, _z_init_encode, _z_msg_ext_encode, _z_msg_ext_make_unit,
    _z_msg_ext_make_zbuf, _z_msg_ext_make_zint, _z_slice_t, _z_t_msg_init_t, _z_wbuf_clear,
    _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

const T_MID_INIT: u8 = 0x01;
const FLAG_T_INIT_S: u8 = 0x40;
const FLAG_T_INIT_A: u8 = 0x20;
const FLAG_T_Z: u8 = 0x80;
const M_FLAG: u8 = 0x10;

const WHATAMI_PEER: u32 = 0x02;

const ENTRY0_ID_UNIT: u8 = 0x00;
const ENTRY1_ID_ZINT: u8 = 0x01;
const ENTRY2_ID_ZBUF: u8 = 0x02;
const ENTRY1_ZINT_VAL: u64 = 42;
const ENTRY2_ZBUF_VAL: [u8; 2] = [0xAB, 0xCD];

fn pack_zid(payload: &[u8]) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..payload.len()].copy_from_slice(payload);
    id
}

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

/// Compose a full InitAck transport-message frame via pico encoders:
/// `[parent_flags|T_MID_INIT, ...body, ...ext_chain]`.
fn pico_initack_with_chain() -> Vec<u8> {
    let parent_flags = FLAG_T_INIT_S | FLAG_T_INIT_A | FLAG_T_Z;
    unsafe {
        let mut wbf = _z_wbuf_make(128, false);
        let msg = _z_t_msg_init_t {
            _zid: _z_id_t {
                id: pack_zid(&[0x01, 0x02, 0x03, 0x04]),
            },
            _cookie: make_slice(&[]),
            _batch_size: 0,
            _whatami: WHATAMI_PEER,
            _req_id_res: 0,
            _seq_num_res: 0,
            _version: PROTOCOL_VERSION,
            _patch: 0,
        };
        assert_eq!(_z_init_encode(&mut wbf, parent_flags, &msg), 0);

        let unit_ext = _z_msg_ext_make_unit(ENTRY0_ID_UNIT);
        let mut zint_ext = _z_msg_ext_make_zint(ENTRY1_ID_ZINT, ENTRY1_ZINT_VAL as usize);
        zint_ext._header |= M_FLAG;
        let mut zbuf_body: _z_slice_t = std::mem::zeroed();
        zbuf_body.start = ENTRY2_ZBUF_VAL.as_ptr();
        zbuf_body.len = ENTRY2_ZBUF_VAL.len();
        let mut zbuf_ext = _z_msg_ext_make_zbuf(ENTRY2_ID_ZBUF, zbuf_body);
        zbuf_ext._header |= M_FLAG;

        assert_eq!(_z_msg_ext_encode(&mut wbf, &unit_ext, true), 0);
        assert_eq!(_z_msg_ext_encode(&mut wbf, &zint_ext, true), 0);
        assert_eq!(_z_msg_ext_encode(&mut wbf, &zbuf_ext, false), 0);

        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let body_and_chain = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);

        let mut wire = Vec::with_capacity(1 + body_and_chain.len());
        wire.push(parent_flags | T_MID_INIT);
        wire.extend_from_slice(&body_and_chain);
        wire
    }
}

// wz-proves: codec-init-body pico->wz partial
#[test]
fn parse_inbound_decodes_ext_chain_from_pico_wire() {
    let wire = pico_initack_with_chain();
    let frame = parse_inbound(&wire).expect("parse_inbound on Z-flagged InitAck");
    match frame {
        InboundFrame::Init {
            is_ack,
            has_ext,
            extensions,
            ..
        } => {
            assert!(is_ack);
            assert!(has_ext, "Z flag must surface as has_ext=true");
            assert_eq!(extensions.len(), 3);

            // Entry 0 — Unit (id=0, M=0, enc=0, Z=1 chain-continue).
            assert_eq!(extensions[0].ext_id(), ENTRY0_ID_UNIT);
            assert!(!extensions[0].m());
            assert_eq!(extensions[0].enc(), 0);
            assert!(extensions[0].z(), "non-terminal entry must keep Z=1");
            assert!(matches!(
                extensions[0].body,
                ExtEntryOwnedVariant::CodecZenohExtUnit(_)
            ));

            // Entry 1 — ZInt (id=1, M=1, enc=1, Z=1 chain-continue,
            // value=42).
            assert_eq!(extensions[1].ext_id(), ENTRY1_ID_ZINT);
            assert!(extensions[1].m());
            assert_eq!(extensions[1].enc(), 1);
            assert!(extensions[1].z());
            match &extensions[1].body {
                ExtEntryOwnedVariant::CodecZenohExtZint(b) => {
                    assert_eq!(b.value, ENTRY1_ZINT_VAL)
                }
                _ => panic!("entry 1 must decode to ZInt"),
            }

            // Entry 2 — ZBuf (id=2, M=1, enc=2, Z=0 terminator,
            // payload [0xAB, 0xCD]).
            assert_eq!(extensions[2].ext_id(), ENTRY2_ID_ZBUF);
            assert!(extensions[2].m());
            assert_eq!(extensions[2].enc(), 2);
            assert!(!extensions[2].z(), "terminal entry must clear Z");
            match &extensions[2].body {
                ExtEntryOwnedVariant::CodecZenohExtZbuf(b) => {
                    assert_eq!(b.value.as_slice(), ENTRY2_ZBUF_VAL.as_slice())
                }
                _ => panic!("entry 2 must decode to ZBuf"),
            }
        }
        _ => panic!("expected Init variant"),
    }
}

/// A minimal InitAck carrying `entries` Unit extensions (id 0, M=0, a
/// 1-byte header each, no body), every one announcing a next (Z=1) and, when
/// `terminated`, the last one clearing it.
fn initack_with_unit_chain(entries: usize, terminated: bool) -> Vec<u8> {
    let parent_flags = FLAG_T_INIT_S | FLAG_T_INIT_A | FLAG_T_Z;
    let mut wire = Vec::new();
    wire.push(parent_flags | T_MID_INIT);
    // Minimal InitAck body — version + cbyte + zid(1 byte) +
    // sn_res + batch_size(2) + cookie_len=0. zid_len_m1=0 makes the
    // high nibble 0, so cbyte = wire-form whatami only.
    let cbyte = ((WHATAMI_PEER >> 1) & 0x03) as u8;
    wire.extend_from_slice(&[
        PROTOCOL_VERSION, // version
        cbyte,
        0xAA, // zid
        0x00, // sn_res
        0x00,
        0x00, // batch_size LE
        0x00, // VLE cookie_len=0
    ]);
    wire.resize(wire.len() + entries, 0x80);
    if terminated {
        *wire.last_mut().expect("a chain of at least one entry") = 0x00;
    }
    wire
}

// wz-proves: none -- hand-synthesized wire; no foreign code invoked
#[test]
fn ext_chain_overflow_rejects_unbounded_continuation() {
    // A whole chain one entry past the bound: the wire is read, and the
    // participant's capacity refuses the entry past it.
    let past_the_bound = initack_with_unit_chain(MAX_EXT_CHAIN_DEPTH + 1, true);
    assert_eq!(
        parse_inbound(&past_the_bound).err(),
        Some(InboundParseError::ExtChainOverflow),
        "a chain past the bound must surface ExtChainOverflow"
    );

    // CONTROL: the same chain at the bound is read whole.
    let at_the_bound = initack_with_unit_chain(MAX_EXT_CHAIN_DEPTH, true);
    assert!(
        matches!(
            parse_inbound(&at_the_bound),
            Ok(InboundFrame::Init { has_ext: true, .. })
        ),
        "a chain at the bound must be read"
    );

    // A chain whose last entry still announces a next, cut by the end of the
    // unit, is a wire that cannot be read, whatever its length: zenoh's
    // reader and zenoh-pico's walk the chain until the flag clears and fail
    // on the missing header, and the bound judges only a chain that was read.
    for entries in [MAX_EXT_CHAIN_DEPTH, MAX_EXT_CHAIN_DEPTH + 1] {
        let cut = initack_with_unit_chain(entries, false);
        assert_eq!(
            parse_inbound(&cut).err(),
            Some(InboundParseError::Codec(CodecError::NeedMoreBytes)),
            "an unterminated chain of {entries} entries is a truncated wire"
        );
    }
}

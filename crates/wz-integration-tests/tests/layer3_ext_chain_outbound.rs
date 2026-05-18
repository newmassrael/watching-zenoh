// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop — R68b ext-chain encode integration.
//!
//! Validates `SessionLinkActions::encode_init_with_role` (the
//! ext-chain-aware outbound encoder) against zenoh-pico's
//! `_z_init_encode` + `_z_msg_ext_encode` chain. Bypasses the
//! `dispatch_script` Lua-singleton path so two `#[test]`s in this
//! binary can each construct their own `SessionLinkActions`
//! without racing on the process-global `INSTALLED` OnceLock.
//!
//! Wire shape exercised:
//!   `[header_byte, ...init_body, ...ext_chain]`
//!
//! where `header_byte = T_MID_INIT | FLAG_T_INIT_S | FLAG_T_INIT_A
//! | FLAG_T_Z` for the populated chain, and `... | FLAG_T_Z` is
//! dropped (zero) for the empty-chain case.

use std::sync::Arc;

use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
use wz_codecs::ext_unit::ExtUnit;
use wz_codecs::ext_zbuf::ExtZbuf;
use wz_codecs::ext_zint::ExtZint;
use wz_runtime_tokio::session_glue::{BoxedLinkDriver, ExtChainRole, SessionLinkActions};
use wz_runtime_tokio::Reliability;
use wz_runtime_tokio_test_support::fixture_session_init_params;
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

// Fixture inputs — match fixture_session_init_params().
const FIXTURE_VERSION: u8 = 0x05;
const FIXTURE_WHATAMI_API: u8 = 0x02; // Peer
const FIXTURE_ZID: [u8; 4] = [0x01, 0x01, 0x01, 0x01];
const FIXTURE_SEQ_NUM_RES: u8 = 0;
const FIXTURE_REQ_ID_RES: u8 = 0;
const FIXTURE_BATCH_SIZE: u16 = 0;
const FIXTURE_COOKIE: &[u8] = &[];

// Oracle ext-chain values — same as layer3_ext_envelope.rs.
const ENTRY0_ID_UNIT: u8 = 0x00;
const ENTRY1_ID_ZINT: u8 = 0x01;
const ENTRY2_ID_ZBUF: u8 = 0x02;
const ENTRY1_ZINT_VAL: u64 = 42;
const ENTRY2_ZBUF_VAL: [u8; 2] = [0xAB, 0xCD];

/// Inert link driver — `SessionLinkActions::new` requires one but
/// the encode-only path in this test never reaches `send_blocking`.
struct NoopDriver;
impl BoxedLinkDriver for NoopDriver {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) {}
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

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

fn pico_init_body(parent_flags: u8) -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(128, false);
        let msg = _z_t_msg_init_t {
            _zid: _z_id_t {
                id: pack_zid(&FIXTURE_ZID),
            },
            _cookie: make_slice(FIXTURE_COOKIE),
            _batch_size: FIXTURE_BATCH_SIZE,
            _whatami: FIXTURE_WHATAMI_API as u32,
            _req_id_res: FIXTURE_REQ_ID_RES,
            _seq_num_res: FIXTURE_SEQ_NUM_RES,
            _version: FIXTURE_VERSION,
            _patch: 0,
        };
        assert_eq!(_z_init_encode(&mut wbf, parent_flags, &msg), 0);
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let body = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        body
    }
}

fn pico_oracle_ext_chain() -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(32, false);

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
        let chain = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        chain
    }
}

/// Build the wz-side oracle chain — 3 ExtEntry records with the
/// non-Z bits author-set (`ext_id`, `M`, `enc`). The encoder owns
/// the Z bit per chain position.
fn wz_oracle_chain() -> Vec<ExtEntry> {
    let mut unit = ExtEntry::default();
    unit.set_ext_id(ENTRY0_ID_UNIT);
    unit.set_enc(0);
    unit.body = ExtEntryVariant::CodecZenohExtUnit(ExtUnit::default());

    let mut zint = ExtEntry::default();
    zint.set_ext_id(ENTRY1_ID_ZINT);
    zint.set_m(true);
    zint.set_enc(1);
    zint.body = ExtEntryVariant::CodecZenohExtZint(ExtZint {
        value: ENTRY1_ZINT_VAL,
    });

    let mut zbuf = ExtEntry::default();
    zbuf.set_ext_id(ENTRY2_ID_ZBUF);
    zbuf.set_m(true);
    zbuf.set_enc(2);
    zbuf.body = ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
        value_len: ENTRY2_ZBUF_VAL.len() as u64,
        value: ENTRY2_ZBUF_VAL.to_vec(),
    });

    vec![unit, zint, zbuf]
}

#[test]
fn encode_init_with_ext_chain_byte_equiv_to_pico() {
    let parent_flags_no_z = FLAG_T_INIT_S | FLAG_T_INIT_A;
    let mut expected = Vec::new();
    expected.push((parent_flags_no_z | FLAG_T_Z) | T_MID_INIT);
    expected.extend_from_slice(&pico_init_body(parent_flags_no_z));
    expected.extend_from_slice(&pico_oracle_ext_chain());

    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopDriver);
    let actions = SessionLinkActions::new(driver, fixture_session_init_params());
    actions.set_ext_chain(ExtChainRole::InitAck, wz_oracle_chain());

    let actual = actions.encode_init_with_role(/*is_ack=*/ true, /*cookie_override=*/ None, ExtChainRole::InitAck);
    assert_eq!(
        actual, expected,
        "wz InitAck encode with ext chain must byte-match pico reference"
    );
}

#[test]
fn encode_init_with_explicit_empty_chain_omits_z_flag_and_trailing_bytes() {
    let parent_flags = FLAG_T_INIT_S | FLAG_T_INIT_A;
    let mut expected = Vec::new();
    expected.push(parent_flags | T_MID_INIT);
    expected.extend_from_slice(&pico_init_body(parent_flags));

    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopDriver);
    let actions = SessionLinkActions::new(driver, fixture_session_init_params());
    // R121f1 — `SessionLinkActions::new` now seeds the Init ext chains
    // with the wire-spec-mandatory patch entry; this test re-asserts
    // the encoder's "empty chain → no Z flag + no trailing bytes"
    // contract by explicitly clearing the slot first.
    actions.set_ext_chain(ExtChainRole::InitAck, Vec::new());

    let actual = actions.encode_init_with_role(/*is_ack=*/ true, /*cookie_override=*/ None, ExtChainRole::InitAck);
    assert_eq!(
        actual, expected,
        "explicitly-empty chain wire must omit Z flag + trailing bytes"
    );
    assert_eq!(actual[0] & FLAG_T_Z, 0, "Z flag must be clear");
}

#[test]
fn ext_chain_role_isolation() {
    // Setting InitSyn chain must not bleed into InitAck encode.
    // R121f1 — clear both default Init ext chains first so the
    // post-set state isolates exactly one role's override.
    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopDriver);
    let actions = SessionLinkActions::new(driver, fixture_session_init_params());
    actions.set_ext_chain(ExtChainRole::InitSyn, Vec::new());
    actions.set_ext_chain(ExtChainRole::InitAck, Vec::new());
    actions.set_ext_chain(ExtChainRole::InitSyn, wz_oracle_chain());

    let init_ack_wire =
        actions.encode_init_with_role(/*is_ack=*/ true, /*cookie_override=*/ None, ExtChainRole::InitAck);
    assert_eq!(init_ack_wire[0] & FLAG_T_Z, 0, "InitAck unaffected by InitSyn chain");

    let init_syn_wire =
        actions.encode_init_with_role(/*is_ack=*/ false, /*cookie_override=*/ None, ExtChainRole::InitSyn);
    assert_ne!(init_syn_wire[0] & FLAG_T_Z, 0, "InitSyn role chain populates Z");
}

/// R121f1 — `SessionLinkActions::new()` seeds the Init ext chains
/// with the wire-spec-mandatory patch extension entry
/// (`_Z_MSG_EXT_ID_INIT_PATCH = 0x07 | _Z_MSG_EXT_ENC_ZINT = 0x27`,
/// `body = VLE(_Z_CURRENT_PATCH = 1) = 0x01`). Without this seed,
/// zenoh-pico's accept-side size negotiation caps `iam._patch` to
/// `_Z_NO_PATCH = 0`, the InitAck header carries a stale `Z=1`
/// flag with no trailing ext bytes, and the wz initiator's parser
/// reports `NeedMoreBytes` (closure of the R121f foreign-interop
/// carry; see `default_init_patch_ext_entry` in session_glue for
/// the wire-spec citation).
#[test]
fn default_session_actions_seed_init_chains_with_patch_extension() {
    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopDriver);
    let actions = SessionLinkActions::new(driver, fixture_session_init_params());

    let init_syn = actions.encode_init_with_role(
        /*is_ack=*/ false, /*cookie_override=*/ None, ExtChainRole::InitSyn,
    );
    let init_ack = actions.encode_init_with_role(
        /*is_ack=*/ true, /*cookie_override=*/ None, ExtChainRole::InitAck,
    );

    assert_ne!(init_syn[0] & FLAG_T_Z, 0, "default InitSyn wire must set Z");
    assert_ne!(init_ack[0] & FLAG_T_Z, 0, "default InitAck wire must set Z");

    // Last two bytes of each Init frame = [patch_ext_header,
    // VLE(_Z_CURRENT_PATCH)] = [0x27, 0x01]. `encode_ext_chain`
    // clears the Z bit on the single-entry chain's last entry, so
    // the header byte is 0x27 unmodified.
    assert_eq!(
        &init_syn[init_syn.len() - 2..],
        &[0x27u8, 0x01u8],
        "default InitSyn must terminate with the patch-ext entry",
    );
    assert_eq!(
        &init_ack[init_ack.len() - 2..],
        &[0x27u8, 0x01u8],
        "default InitAck must terminate with the patch-ext entry",
    );
}

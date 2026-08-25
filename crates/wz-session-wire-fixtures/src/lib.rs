// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! Synthetic zenoh session handshake wire bytes — the single SSOT for the
//! hand-crafted frames the session-FSM drive tests and the MCU acceptor e2e
//! route through the production `parse_inbound` / FSM decoders.
//!
//! These are the "independent oracle": the bytes are hand-rolled here per
//! the zenoh-pico transport layout, deliberately NOT produced by the wz
//! encoder, so a drive test that feeds them through the production DECODER
//! is checking the decoder against an independent source. The byte layouts
//! are themselves verified byte-identical against zenoh-pico by the
//! `wz-integration-tests` `layer3_*` codec tests; this crate is the one
//! place they live.
//!
//! Hosting them once (rather than the pre-Stage-5 copy in each of the three
//! `wz-runtime-tokio` session-FSM test files + a fourth in
//! `wz-mcu-session-acceptor`) keeps the wire format a single editable point:
//! a spec change touches one definition, not four drifting ones.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

// ── Transport-header constants (zenoh-pico transport.h; mirror the private
//    `wz_session_core` / session_glue `wire_const`). Public so a test that
//    hand-builds a one-off variant (a different zid, a forged cookie) reuses
//    the same MID/flag vocabulary instead of redeclaring it.

/// `_Z_MID_T_INIT`.
pub const T_MID_INIT: u8 = 0x01;
/// `_Z_MID_T_OPEN`.
pub const T_MID_OPEN: u8 = 0x02;
/// `_Z_MID_T_KEEP_ALIVE`.
pub const T_MID_KEEP_ALIVE: u8 = 0x04;
/// `_Z_MID_T_FRAME`.
pub const T_MID_FRAME: u8 = 0x05;
/// `_Z_MID_T_FRAGMENT` (transport.h §5.M).
pub const T_MID_FRAGMENT: u8 = 0x06;
/// `_Z_FLAG_T_FRAGMENT_R` — reliable fragment channel (1<<5).
pub const FLAG_T_FRAGMENT_R: u8 = 0x20;
/// `_Z_FLAG_T_FRAGMENT_M` — more-fragments-follow bit (1<<6).
pub const FLAG_T_FRAGMENT_M: u8 = 0x40;
/// `_Z_FLAG_T_INIT_S` — InitSyn present / sizing fields follow.
pub const FLAG_T_INIT_S: u8 = 0x40;
/// `_Z_FLAG_T_INIT_A` — InitAck (the `A` discriminator on the INIT MID).
pub const FLAG_T_INIT_A: u8 = 0x20;
/// `_Z_FLAG_T_FRAME_R` — reliable Frame.
pub const FLAG_T_FRAME_R: u8 = 0x20;

/// The Initiator zid the crafted `InitSyn` advertises (cbyte high nibble = 3
/// => 4-byte zid). The Accepting side binds its minted cookie to these bytes
/// (R86), so a test computing the expected cookie passes THIS to the HMAC.
pub const FIXTURE_PEER_ZID: [u8; 4] = [0xB0, 0xB1, 0xB2, 0xB3];

/// The responder zid the crafted `InitAck` carries (distinct from
/// [`FIXTURE_PEER_ZID`] so an Initiator-side test can tell the two apart).
pub const FIXTURE_LISTENER_ZID: [u8; 4] = [0xA0, 0xA1, 0xA2, 0xA3];

/// Minimal `InitSyn` (parent flag `FLAG_T_INIT_S`, no `_A` so no cookie):
/// version, cbyte (whatami=Peer wire 0x01 | (zid_len-1)<<4), 4-byte
/// [`FIXTURE_PEER_ZID`], sn_res, batch_size LE u16.
pub fn craft_initsyn_wire() -> Vec<u8> {
    let mut wire = vec![
        FLAG_T_INIT_S | T_MID_INIT,
        0x05, // version
        0x31, // cbyte: whatami=Peer wire(0x01), zid_len=4 (high nibble = 3)
    ];
    wire.extend_from_slice(&FIXTURE_PEER_ZID);
    wire.extend_from_slice(&[
        0x00, // sn_res (seq=0, req=0)
        0x00, 0x00, // batch_size LE u16 = 0
    ]);
    wire
}

/// `InitAck` (parent flags `FLAG_T_INIT_S | FLAG_T_INIT_A`) carrying
/// [`FIXTURE_LISTENER_ZID`] and a single-byte-VLE-length `cookie`. Cookie
/// fields are gated by `FLAG_T_INIT_A` per zenoh-pico transport.h §5.M.
pub fn craft_initack_wire(cookie: &[u8]) -> Vec<u8> {
    assert!(
        cookie.len() < 0x80,
        "fixture: single-byte VLE cookie_len only"
    );
    let mut wire = vec![
        FLAG_T_INIT_S | FLAG_T_INIT_A | T_MID_INIT,
        0x05, // version
        0x31, // cbyte: whatami=Peer, zid_len=4
    ];
    wire.extend_from_slice(&FIXTURE_LISTENER_ZID);
    wire.extend_from_slice(&[
        0x00, // sn_res
        0x00,
        0x00,               // batch_size LE u16
        cookie.len() as u8, // VLE cookie_len (< 0x80 single byte)
    ]);
    wire.extend_from_slice(cookie);
    wire
}

/// R311kc — [`craft_initack_wire`] with an explicit sizing advertisement:
/// the packed `sn_res` byte (`(seq & 0x03) | ((req & 0x03) << 2)`) and the
/// LE `batch_size` are caller-supplied so the InitAck params-validation
/// tests can craft an acceptor that ENLARGES a parameter beyond the
/// initiator's InitSyn (the pico
/// `_Z_ERR_TRANSPORT_OPEN_SN_RESOLUTION` rejection condition,
/// unicast/transport.c:123-140). `craft_initack_wire` keeps the all-zero
/// caps the conforming-handshake tests rely on.
pub fn craft_initack_wire_with_caps(cookie: &[u8], sn_res_byte: u8, batch_size: u16) -> Vec<u8> {
    assert!(
        cookie.len() < 0x80,
        "fixture: single-byte VLE cookie_len only"
    );
    let mut wire = vec![
        FLAG_T_INIT_S | FLAG_T_INIT_A | T_MID_INIT,
        0x05, // version
        0x31, // cbyte: whatami=Peer, zid_len=4
    ];
    wire.extend_from_slice(&FIXTURE_LISTENER_ZID);
    wire.push(sn_res_byte);
    wire.extend_from_slice(&batch_size.to_le_bytes());
    wire.push(cookie.len() as u8); // VLE cookie_len (< 0x80 single byte)
    wire.extend_from_slice(cookie);
    wire
}

/// `_Z_FLAG_T_Z` — the transport header's chain-continuation bit: an ext
/// chain follows the message body.
pub const FLAG_T_Z: u8 = 0x80;

/// `_Z_MSG_EXT_ID_INIT_PATCH | _Z_MSG_EXT_ENC_ZINT` — the `0x7` protocol
/// patch extension's header byte in the establishment ext space, with the
/// mandatory bit CLEAR and the chain-continuation bit CLEAR (a lone,
/// final entry). Both references spell it this way: zenoh
/// `init::ext::Patch = zextz64!(0x7, false)`
/// (`commons/zenoh-protocol/src/transport/init.rs:174`), zenoh-pico
/// `_Z_MSG_EXT_ID_INIT_PATCH (0x07 | _Z_MSG_EXT_ENC_ZINT)`
/// (`include/zenoh-pico/protocol/ext.h:48`).
pub const EXT_HDR_INIT_PATCH_ZINT: u8 = 0x27;

/// R311y817 — the `0x7` PATCH ext as a lone terminal chain entry: header
/// byte then the level as a single-byte VLE. Appended to an Init whose
/// parent header carries [`FLAG_T_Z`].
fn patch_ext_chain(level: u8) -> [u8; 2] {
    assert!(level < 0x80, "fixture: single-byte VLE patch level only");
    [EXT_HDR_INIT_PATCH_ZINT, level]
}

/// R311y817 — [`craft_initack_wire`] carrying a `0x7` PATCH extension at
/// `patch_level`, so an initiator-side test can present the acceptor
/// announcement both references REFUSE when it exceeds the InitSyn's
/// (zenoh `PatchFsm::recv_init_ack`'s `bail!` at
/// `unicast/establishment/ext/patch.rs:78-84`; zenoh-pico's
/// `_Z_ERR_GENERIC` at `unicast/transport.c:142-148`).
///
/// Caps are the all-zero conforming advertisement, which is what makes
/// this fixture DISCRIMINATING: a rejection it produces cannot be the
/// size-parameter rule firing, because none of the three sizes moved.
pub fn craft_initack_wire_with_patch(cookie: &[u8], patch_level: u8) -> Vec<u8> {
    assert!(
        cookie.len() < 0x80,
        "fixture: single-byte VLE cookie_len only"
    );
    let mut wire = vec![
        FLAG_T_Z | FLAG_T_INIT_S | FLAG_T_INIT_A | T_MID_INIT,
        0x05, // version
        0x31, // cbyte: whatami=Peer, zid_len=4
    ];
    wire.extend_from_slice(&FIXTURE_LISTENER_ZID);
    wire.extend_from_slice(&[
        0x00, // sn_res (seq=0, req=0) — the conforming advertisement
        0x00,
        0x00,               // batch_size LE u16 = 0
        cookie.len() as u8, // VLE cookie_len (< 0x80 single byte)
    ]);
    wire.extend_from_slice(cookie);
    wire.extend_from_slice(&patch_ext_chain(patch_level));
    wire
}

/// R311y817 — [`craft_initsyn_wire`] carrying a `0x7` PATCH extension at
/// `patch_level`. The ACCEPTOR-role counterpart of
/// [`craft_initack_wire_with_patch`], and the fixture that pins the
/// asymmetry: neither reference refuses an initiator for announcing a
/// level above its own — zenoh's `AcceptFsm::recv_init_syn` stores it
/// unexamined (`ext/patch.rs:168-175`) and answers the `min`, and pico
/// caps with the same `min` (`unicast/transport.c:237-241`).
pub fn craft_initsyn_wire_with_patch(patch_level: u8) -> Vec<u8> {
    let mut wire = vec![
        FLAG_T_Z | FLAG_T_INIT_S | T_MID_INIT,
        0x05, // version
        0x31, // cbyte: whatami=Peer wire(0x01), zid_len=4 (high nibble = 3)
    ];
    wire.extend_from_slice(&FIXTURE_PEER_ZID);
    wire.extend_from_slice(&[
        0x00, // sn_res (seq=0, req=0)
        0x00, 0x00, // batch_size LE u16 = 0
    ]);
    wire.extend_from_slice(&patch_ext_chain(patch_level));
    wire
}

/// `OpenSyn` echoing `cookie` (parent flags 0x00 so the cookie carrier is
/// present and the lease is in ms): lease VLE=0, initial_sn VLE=0,
/// cookie_len VLE, cookie bytes.
pub fn craft_opensyn_wire(cookie: &[u8]) -> Vec<u8> {
    assert!(
        cookie.len() < 0x80,
        "fixture: single-byte VLE cookie_len only"
    );
    let mut wire = vec![
        T_MID_OPEN,
        0x00,               // lease VLE = 0
        0x00,               // initial_sn VLE = 0
        cookie.len() as u8, // cookie_len VLE
    ];
    wire.extend_from_slice(cookie);
    wire
}

/// `_Z_FLAG_T_OPEN_A` — OpenAck (the `A` discriminator on the OPEN MID).
pub const FLAG_T_OPEN_A: u8 = 0x20;

/// R311ke — `OpenAck` (parent flag `FLAG_T_OPEN_A`; no cookie — the
/// cookie rides the Syn only) announcing `initial_sn`: lease VLE=0,
/// initial_sn VLE. Seeds the initiator-side RX SN gate in tests exactly
/// as a real acceptor's OpenAck does.
pub fn craft_openack_wire(initial_sn: u64) -> Vec<u8> {
    assert!(
        initial_sn < 0x80,
        "fixture: single-byte VLE initial_sn only"
    );
    vec![
        FLAG_T_OPEN_A | T_MID_OPEN,
        0x00,             // lease VLE = 0
        initial_sn as u8, // initial_sn VLE
    ]
}

/// Application `Frame` with the `R` (reliable) flag set per `reliable`, a
/// single-byte-VLE `sn`, and an empty payload (decodes to a `FramePayload`
/// with an empty NetworkMessage batch).
pub fn craft_frame_wire(sn: u64, reliable: bool) -> Vec<u8> {
    assert!(sn < 0x80, "fixture: single-byte VLE sn only");
    let header = if reliable {
        FLAG_T_FRAME_R | T_MID_FRAME
    } else {
        T_MID_FRAME
    };
    vec![header, sn as u8]
}

/// Transport `Fragment` (`T_MID_FRAGMENT`): header byte
/// `(R?|M?|T_MID_FRAGMENT)`, a single-byte-VLE `sn`, then the tail
/// `payload`. The body mirrors `T_MID_FRAME` (VLE sn + tail) — only the
/// MID and the R/M header bits differ; no Z (ext) bit, so the reassembly
/// body is `sn + payload`. A chain's non-final fragments set `more`; the
/// final fragment clears it. The concatenated payloads of a chain are the
/// reassembled message (re-parsed as a `Frame` payload by the drive loop).
pub fn craft_fragment_wire(reliable: bool, more: bool, sn: u64, payload: &[u8]) -> Vec<u8> {
    assert!(sn < 0x80, "fixture: single-byte VLE sn only");
    let mut flags = 0u8;
    if reliable {
        flags |= FLAG_T_FRAGMENT_R;
    }
    if more {
        flags |= FLAG_T_FRAGMENT_M;
    }
    let mut wire = vec![flags | T_MID_FRAGMENT, sn as u8];
    wire.extend_from_slice(payload);
    wire
}

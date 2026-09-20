// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2760 — the accept cookie that CARRIES the acceptor's state.
//!
//! ## What this is for, and why the old cookie could not be it
//!
//! `session-unicast-accept`'s standing residual is that wz's acceptor is not
//! stateless: it builds a `SessionActions` and an engine before InitSyn and
//! holds them through the handshake, where zenoh holds nothing. Upstream can
//! hold nothing because its cookie CARRIES the negotiated state —
//! `io/zenoh-transport/src/unicast/establishment/cookie.rs` @
//! `pub(crate) struct Cookie` is zid, whatami, resolution, batch_size, nonce
//! and a `StateAccept` per extension, handed out in InitAck and returned in
//! OpenSyn.
//!
//! wz's cookie is [`crate::signing_key::generate_cookie_hmac_sha256`], which
//! is `HMAC-SHA256(key, nonce ‖ peer_zid)[..16]` — a sixteen-byte TAG. It
//! proves the peer echoed something bound to its zid, and it can carry
//! nothing. That is the structure this module replaces: not where a check
//! happens, but what the cookie IS.
//!
//! ## What it carries, derived rather than chosen
//!
//! The payload is the acceptor's whole InitSyn-derived state, and that set was
//! MEASURED rather than mirrored from upstream. `SessionLinkActions`'s
//! `is_ack: false` arm populates exactly four slots, all pure functions of the
//! InitSyn body: `inbound_peer_zid` and `remote_peer_zid` (both `body.zid`),
//! `peer_whatami` (`body.whatami()`), and `inbound_peer_init_caps`
//! (`PeerInitCaps::from_init_body(body.sn_res, body.batch_size)`).
//!
//! ⚠ THE EXTENSION CHAIN IS NOT AMONG THEM, and checking that is what made
//! this module possible. The `init_syn_ext` / `init_ack_ext` / `open_syn_ext`
//! / `open_ack_ext` slots read like stores of what arrived; every one of their
//! eight consumers is SEND-side (`set_ext_chain`, both `encode_*_with_role`,
//! and five `stage_*` writers), and `init_syn_ext` is initialised to a local
//! `default_init_patch_ext_entry()`. A peer's offers reach the acceptor only
//! as OUTCOMES, through `negotiate_lowlatency_against_peer(peer_offered:
//! bool)` and its qos / compression / shm siblings. So the extension half of
//! the state is a handful of bools — upstream's `StateAccept` shape, arrived
//! at from wz's own code.
//!
//! That matters for size. A raw extension chain would not fit: `ExtEntry`'s
//! own `MAX_ENCODED_BYTES` is 42 and a wz InitSyn may carry six extensions,
//! against a cookie field the generated codec caps at
//! `Option<S::Bytes<128>>` — a cap that is advisory on the Heap storage
//! profile and HARD on the no-alloc Inline one. The outcome form is 30 bytes
//! of payload plus a 16-byte tag.
//!
//! ## What it does NOT do
//!
//! This module is the cookie alone. Nothing here stages the handshake or
//! replays an InitSyn; `accept_and_open_session` is still one atomic call, so
//! the acceptor still holds its engine across the handshake. Building the
//! carrier first is deliberate — the staging cannot be written until there is
//! something for the peer to hand back — and it is why this lands without
//! changing any wire behaviour.

use alloc::vec::Vec;

use crate::signing_key::{cookie_payload_tag, cookie_payload_tag_verify, SigningKey};

/// Bytes of HMAC-SHA256 kept as the authentication tag.
///
/// Sixteen, matching [`crate::signing_key::generate_cookie_hmac_sha256`]'s
/// truncation rather than introducing a second width: the cookie's
/// anti-amplification job is unchanged and a reader comparing the two forms
/// should not have to ask why the tags differ.
pub const COOKIE_TAG_BYTES: usize = 16;

/// The widest zid the protocol admits (`InitBody`'s own 1..=16 bound).
const MAX_ZID_BYTES: usize = 16;

/// The acceptor's InitSyn-derived state, as the cookie carries it.
///
/// Every field is something the acceptor learned from the peer's InitSyn and
/// would otherwise have to REMEMBER between InitAck and OpenSyn. There is
/// nothing here that wz does not already hold in a `SessionLinkActions` slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptCookieState {
    /// The peer's claimed zid (`body.zid`, 1..=16 bytes). Feeds both
    /// `inbound_peer_zid` and `remote_peer_zid`, which take the same value.
    pub peer_zid: Vec<u8>,
    /// The peer's WhatAmI as the raw 2-bit wire form (`body.whatami()`).
    pub peer_whatami: u8,
    /// The peer's packed `sn_res` byte, as `PeerInitCaps` reads it.
    pub sn_res: u8,
    /// The peer's advertised batch size.
    pub batch_size: u16,
    /// The anti-amplification nonce this cookie is bound to — the same role it
    /// has in the tag-only form.
    pub nonce: u64,
    /// The negotiated extension OUTCOMES, in the order
    /// [`AcceptCookieState::flags`] packs them.
    pub lowlatency: bool,
    pub qos: bool,
    pub compression: bool,
    pub shm: bool,
}

/// Why a cookie did not decode.
///
/// ⚠ `Tampered` and `Malformed` are DISTINCT, and collapsing them would lose
/// the only thing a reader can act on: a bad tag is an attacker or a key
/// rotation, while a bad length is this code disagreeing with itself. The
/// tag is checked FIRST, so a malformed verdict is only ever reached for
/// bytes this key actually signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieError {
    /// The tag did not verify against this key.
    Tampered,
    /// The tag verified and the payload still did not parse.
    Malformed,
}

impl AcceptCookieState {
    /// The four outcome bools as one byte.
    ///
    /// A bitset rather than four bytes because the cookie's budget is the
    /// no-alloc profile's 128, and because a fixed width keeps
    /// [`decode_accept_cookie`]'s length check a comparison rather than a
    /// parse loop.
    fn flags(&self) -> u8 {
        u8::from(self.lowlatency)
            | (u8::from(self.qos) << 1)
            | (u8::from(self.compression) << 2)
            | (u8::from(self.shm) << 3)
    }
}

/// Serialise the acceptor's state and authenticate it.
///
/// Layout: `nonce(8) ‖ whatami(1) ‖ sn_res(1) ‖ batch_size(2) ‖ flags(1) ‖
/// zid_len(1) ‖ zid(zid_len) ‖ tag(16)`. Little-endian throughout, matching
/// every other wz wire integer.
///
/// The TAG COVERS THE WHOLE PAYLOAD, not just the zid as the tag-only form
/// did. That is the difference between a cookie a peer may echo and a cookie a
/// peer may REWRITE: every field here is state the acceptor will act on, so
/// each one has to be under the MAC or the peer chooses it.
///
/// Returns `None` when `peer_zid` is outside the protocol's 1..=16, because a
/// cookie for a zid the wire cannot carry is not a value this function should
/// invent.
pub fn encode_accept_cookie(key: &SigningKey, state: &AcceptCookieState) -> Option<Vec<u8>> {
    let zid_len = state.peer_zid.len();
    if zid_len == 0 || zid_len > MAX_ZID_BYTES {
        return None;
    }
    let mut out = Vec::with_capacity(14 + zid_len + COOKIE_TAG_BYTES);
    out.extend_from_slice(&state.nonce.to_le_bytes());
    out.push(state.peer_whatami);
    out.push(state.sn_res);
    out.extend_from_slice(&state.batch_size.to_le_bytes());
    out.push(state.flags());
    out.push(zid_len as u8);
    out.extend_from_slice(&state.peer_zid);
    let t = cookie_payload_tag(key, &out);
    out.extend_from_slice(&t);
    Some(out)
}

/// Verify and parse a cookie this node minted.
///
/// ⚠ THE TAG IS CHECKED BEFORE ANY FIELD IS READ, and `verify_slice` is the
/// `hmac` crate's constant-time comparison rather than `==`. Parsing first
/// would let a peer steer this code with bytes it never signed, and a
/// short-circuiting compare would leak the tag a byte at a time to anyone
/// willing to retry.
pub fn decode_accept_cookie(
    key: &SigningKey,
    bytes: &[u8],
) -> Result<AcceptCookieState, CookieError> {
    if bytes.len() < COOKIE_TAG_BYTES {
        return Err(CookieError::Tampered);
    }
    let (payload, got) = bytes.split_at(bytes.len() - COOKIE_TAG_BYTES);
    // Constant-time, and the key stays inside `signing_key`: see
    // `cookie_payload_tag_verify` for why this is an operation rather than an
    // accessor.
    if !cookie_payload_tag_verify(key, payload, got) {
        return Err(CookieError::Tampered);
    }

    // Past this line the bytes are ours, so a failure is THIS code's
    // disagreement with itself rather than an attacker's.
    if payload.len() < 14 {
        return Err(CookieError::Malformed);
    }
    let nonce = u64::from_le_bytes(
        payload[0..8]
            .try_into()
            .map_err(|_| CookieError::Malformed)?,
    );
    let peer_whatami = payload[8];
    let sn_res = payload[9];
    let batch_size = u16::from_le_bytes(
        payload[10..12]
            .try_into()
            .map_err(|_| CookieError::Malformed)?,
    );
    let flags = payload[12];
    let zid_len = payload[13] as usize;
    if zid_len == 0 || zid_len > MAX_ZID_BYTES || payload.len() != 14 + zid_len {
        return Err(CookieError::Malformed);
    }
    Ok(AcceptCookieState {
        peer_zid: payload[14..14 + zid_len].to_vec(),
        peer_whatami,
        sn_res,
        batch_size,
        nonce,
        lowlatency: flags & 0b0001 != 0,
        qos: flags & 0b0010 != 0,
        compression: flags & 0b0100 != 0,
        shm: flags & 0b1000 != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn key() -> SigningKey {
        SigningKey::new(vec![7u8; 32]).expect("32 bytes is the RFC §5.M minimum")
    }

    fn state() -> AcceptCookieState {
        AcceptCookieState {
            peer_zid: vec![0xAB; 4],
            peer_whatami: 1,
            sn_res: 2,
            batch_size: 65_535,
            nonce: 0x0123_4567_89AB_CDEF,
            lowlatency: true,
            qos: false,
            compression: true,
            shm: false,
        }
    }

    /// EVERY field survives the round trip, which is the whole claim: a cookie
    /// that carried only some of them would let the acceptor rebuild a state
    /// that is not the one it had.
    ///
    /// Asserted as ONE `assert_eq!` on the struct rather than field by field,
    /// so a field ADDED to `AcceptCookieState` and forgotten in the codec
    /// fails here instead of being silently unchecked.
    #[test]
    fn every_field_survives_the_round_trip() {
        let k = key();
        let wire = encode_accept_cookie(&k, &state()).expect("a 4-byte zid encodes");
        let back = decode_accept_cookie(&k, &wire).expect("our own cookie verifies");
        assert_eq!(back, state());
    }

    /// The cookie fits the wire field that has to carry it.
    ///
    /// `InitBody`'s generated `cookie` is `Option<S::Bytes<128>>`, a cap that
    /// is ADVISORY on the Heap profile and HARD on the no-alloc Inline one —
    /// so a cookie that fit only on AP would strand the MCU acceptor. The
    /// widest zid the protocol admits is the worst case and is what this
    /// measures.
    #[test]
    fn the_widest_cookie_fits_the_generated_field() {
        let k = key();
        let mut s = state();
        s.peer_zid = vec![0xFF; MAX_ZID_BYTES];
        let wire = encode_accept_cookie(&k, &s).expect("a 16-byte zid encodes");
        assert_eq!(wire.len(), 14 + MAX_ZID_BYTES + COOKIE_TAG_BYTES);
        assert!(
            wire.len() <= 128,
            "the widest cookie is {} bytes and the generated field caps at 128",
            wire.len()
        );
    }

    /// A FLIPPED PAYLOAD BYTE IS REFUSED, and this is the arm the tag exists
    /// for: every field is state the acceptor acts on, so a peer that could
    /// rewrite one would be choosing it.
    ///
    /// The loop covers EVERY payload byte rather than one: a MAC that covered
    /// only the zid — which is what the tag-only form did — would pass a test
    /// that flipped the zid alone.
    ///
    /// CONTROL, run both ways because the first attempt was not a control at
    /// all. Narrowing the tag to the zid on the SIGNING side alone reds
    /// `every_field_survives_the_round_trip` instead of this test — an
    /// encode/decode asymmetry, not the property under test. Narrowing BOTH
    /// sides keeps the round trip green and reds this test at
    /// "payload byte 0 was not under the MAC", byte 0 being the nonce. That
    /// is the claim: the tag covers the whole payload, and the tag-only form
    /// covered the zid.
    #[test]
    fn a_flipped_byte_anywhere_in_the_payload_is_refused() {
        let k = key();
        let wire = encode_accept_cookie(&k, &state()).expect("encodes");
        let payload_len = wire.len() - COOKIE_TAG_BYTES;
        for i in 0..payload_len {
            let mut bad = wire.clone();
            bad[i] ^= 0x01;
            assert_eq!(
                decode_accept_cookie(&k, &bad),
                Err(CookieError::Tampered),
                "payload byte {i} was not under the MAC"
            );
        }
    }

    /// A cookie minted under one key does not verify under another.
    #[test]
    fn another_key_does_not_verify() {
        let wire = encode_accept_cookie(&key(), &state()).expect("encodes");
        let other = SigningKey::new(vec![9u8; 32]).expect("32 bytes");
        assert_eq!(
            decode_accept_cookie(&other, &wire),
            Err(CookieError::Tampered)
        );
    }

    /// A zid the wire cannot carry is refused at encode rather than minted.
    #[test]
    fn a_zid_outside_the_protocol_bound_does_not_encode() {
        let k = key();
        let mut s = state();
        s.peer_zid = vec![];
        assert!(encode_accept_cookie(&k, &s).is_none());
        s.peer_zid = vec![0u8; MAX_ZID_BYTES + 1];
        assert!(encode_accept_cookie(&k, &s).is_none());
    }
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the Z_EXT_AUTH establishment extension wire shape
//! (`session-extauth`).
//!
//! zenoh carries the auth handshake state as an extension on the Init and
//! Open transport messages: `pub type Auth = zextzbuf!(0x3, false)` at BOTH
//! `commons/zenoh-protocol/src/transport/init.rs:156` and `open.rs:121` — ext
//! id `0x3`, the `ExtZbuf` encoding (opaque byte payload), and NO mandatory
//! (`_Z_MSG_EXT_FLAG_M` = `0x10`) bit, so a peer that does not negotiate auth
//! drops the extension silently rather than rejecting the handshake. The
//! payload is the negotiated method's challenge / response bytes, multi-stepped
//! across the existing four-message exchange (InitSyn -> InitAck -> OpenSyn ->
//! OpenAck) — no new session FSM state (the OQ-W10/W2 resolution: the auth ext
//! is side-state on the existing messages, not an intra-Opening sub-region).
//!
//! This module is the codec LAYER only — the `(0x3, ENC_ZBUF, ExtZbuf body)`
//! envelope on Init / Open. The method-agnostic dispatch (the wz mirror of
//! zenoh `establishment/ext/auth/mod.rs`'s OpenFsm / AcceptFsm) and the
//! concrete methods (usrpwd / pubkey) are follow-on atoms that consume these
//! helpers. It mirrors the [`crate::attachment`] ext codec precedent (the same
//! ExtZbuf shape on the Push / Query carriers) but is its own SSOT because the
//! auth ext is a distinct concern on a distinct carrier (the establishment
//! Init / Open, not the data-plane Push / Query), with its own ext id space.

use crate::codec_owned::owned_bytes;
use sce_forge_runtime::codec::CodecError;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;

/// Z_EXT_AUTH ext id on the Init / Open establishment messages — zenoh
/// `init.rs:156` / `open.rs:121` `zextzbuf!(0x3, false)`. Distinct from the
/// data-plane attachment ext (also `0x03` but on the Push / Query carrier);
/// establishment messages have their own ext id space (0x1 QoS, 0x2 Shm,
/// 0x3 Auth, 0x4 MultiLink, 0x5 LowLatency, 0x6 Compression, 0x7 Patch).
pub const AUTH_EXT_ID: u8 = 0x03;

/// ENC_ZBUF marker packed into the ext header high bits: the 2-bit encoding
/// field (`0b10`) shifted into bits 5..6 (`0b10 << 5 = 0x40`). The auth ext is
/// non-mandatory, so the `0x10` mandatory bit is never set.
const AUTH_EXT_HEADER_ENC_ZBUF: u8 = 0x40;

/// Build the Z_EXT_AUTH `ExtEntry` carrying `payload` (the negotiated method's
/// challenge / response bytes). The surrounding codec applies the
/// chain-continuation `Z` bit; this helper emits the entry with `Z` clear
/// (terminator), so a caller appending it as the sole / last establishment ext
/// needs no fix-up. Fallible only on the `no_std` profile, where the owned
/// mirror is a bounded `heapless::Vec` (auth payloads — an 8-byte nonce, an
/// HMAC, an RSA signature — ride the AP `alloc` profile, where any length fits).
pub fn encode_auth_ext(payload: &[u8]) -> Result<ExtEntryOwned, CodecError> {
    Ok(ExtEntryOwned {
        header: AUTH_EXT_HEADER_ENC_ZBUF | AUTH_EXT_ID,
        body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
            value_len: payload.len() as u64,
            value: owned_bytes(payload)?,
        }),
    })
}

/// Project the Z_EXT_AUTH payload from an establishment ext chain. Matches on
/// `(AUTH_EXT_ID, ExtZbuf body)`; the `ExtZbuf` variant is itself the
/// decode-time witness that the header carried the ENC_ZBUF encoding, so no
/// separate `enc()` test is needed. Returns the borrowed payload; a caller
/// needing ownership maps with `<[u8]>::to_vec`. `None` when no auth ext is
/// present (the peer did not negotiate auth) — the admit-by-default path.
pub fn decode_auth_ext(extensions: &[ExtEntryOwned]) -> Option<&[u8]> {
    for ext in extensions {
        if ext.ext_id() == AUTH_EXT_ID {
            if let ExtEntryOwnedVariant::CodecZenohExtZbuf(z) = &ext.body {
                return Some(z.value.as_slice());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips the encode helper against the decode helper and locks the
    /// on-the-wire header byte (`0x40 | 0x03 = 0x43`) — the ENC_ZBUF | auth-id
    /// shape zenoh emits for `init::ext::Auth` / `open::ext::Auth`.
    #[test]
    fn auth_ext_encode_decode_round_trip() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let ext = encode_auth_ext(&payload).unwrap();
        assert_eq!(ext.header, 0x43, "ENC_ZBUF (0x40) | AUTH_EXT_ID (0x03)");
        assert_eq!(decode_auth_ext(&[ext]), Some(payload.as_slice()));
    }

    /// An empty payload round-trips (the InitSyn auth ext can be empty — the
    /// peer advertises auth without yet carrying a challenge).
    #[test]
    fn auth_ext_empty_payload_round_trips() {
        let ext = encode_auth_ext(&[]).unwrap();
        assert_eq!(decode_auth_ext(&[ext]), Some([].as_slice()));
    }

    /// A chain with no auth ext (or only a foreign ext id) decodes to `None` —
    /// the admit-by-default path for a peer that did not negotiate auth.
    #[test]
    fn decode_misses_a_chain_without_the_auth_ext() {
        assert_eq!(decode_auth_ext(&[]), None);
        // A foreign establishment ext (e.g. a 0x07 Patch-shaped entry) is not
        // mistaken for the auth ext.
        let foreign = ExtEntryOwned {
            header: AUTH_EXT_HEADER_ENC_ZBUF | 0x07,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: 1,
                value: owned_bytes(&[0xAB]).unwrap(),
            }),
        };
        assert_eq!(decode_auth_ext(&[foreign]), None);
    }
}

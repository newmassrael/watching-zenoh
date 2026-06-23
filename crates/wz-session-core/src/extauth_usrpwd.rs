// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The usrpwd auth method (`access-extauth-usrpwd`) — the wz mirror of zenoh
//! `establishment/ext/auth/usrpwd.rs`. A username/password challenge-response
//! [`AuthMethod`] on the Z_EXT_AUTH dispatch (method id `0x2`).
//!
//! # Wire (zenoh-faithful, cross-impl with zenohd)
//!
//! - InitSyn = `Unit`         — the open side offers usrpwd (it has credentials)
//! - InitAck = `Z64(nonce)`   — the accept side's challenge
//! - OpenSyn = `Zbuf{user, hmac}` — `hmac = HMAC-SHA3-256(nonce.to_le_bytes(), password)`
//! - OpenAck = `Unit`         — accepted
//!
//! zenoh's `zenoh_crypto::hmac::sign` is `Hmac::<Sha3_256>` (commons/zenoh-crypto/
//! src/hmac.rs:19) — SHA3-256, NOT the SHA-2 the cookie [`crate::signing_key`]
//! uses — so usrpwd pulls the `sha3` crate (under this feature). The OpenSyn
//! `{user, hmac}` body is zenoh `Zenoh080`'s two-`ZBuf` encoding (a VLE length
//! then the bytes, twice), the read twin of [`SceCursor::read_vle_u64`].
//!
//! # Scope
//!
//! This is the method KERNEL: the credential logic + the wire codec + the HMAC,
//! unit-tested through [`AuthDispatch`]. The challenge nonce is INJECTED at
//! construction (the no_std core carries no RNG — `getrandom` has no bare-metal
//! backend; the live handshake wiring supplies a per-handshake random nonce).
//! Wiring `AuthDispatch` into the live Init/Open exchange + a wz<->zenohd
//! interop e2e are follow-on atoms.

use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sce_forge_runtime::codec::SceCursor;
use sha3::Sha3_256;

use crate::auth_dispatch::{AuthError, AuthMethod, AuthSubExt};
use crate::vle::encode_vle_u64_into;

/// usrpwd method id within the auth ext (zenoh `id::USRPWD`).
const USRPWD_ID: u8 = 0x2;

/// HMAC-SHA3-256 sign — zenoh `zenoh_crypto::hmac::sign` (`Hmac::<Sha3_256>`);
/// key = the InitAck nonce's little-endian bytes, msg = the password.
fn hmac_sha3_256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha3_256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time HMAC-SHA3-256 TAG verify (`Mac::verify_slice`). Hardened over
/// zenoh's plain `!=` (identical wire; the tag comparison is timing-safe). NOTE:
/// this hardens ONLY the tag compare — the surrounding user lookup still returns
/// early on an unknown user (a username-enumeration timing oracle, the same as
/// zenoh `usrpwd.rs:418`). Closing that needs a dummy-HMAC on the miss path; it
/// is deferred to the live-handshake atom (it matters only over a real network,
/// which usrpwd assumes is already TLS/QUIC-encrypted underneath).
fn hmac_sha3_256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    let mut mac =
        <Hmac<Sha3_256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.verify_slice(tag).is_ok()
}

/// Read a VLE length then that many bytes (one zenoh `ZBuf`).
fn read_vle_bytes(cursor: &mut SceCursor<'_>) -> Result<Vec<u8>, AuthError> {
    let len = cursor.read_vle_u64().map_err(|_| AuthError::Decode)? as usize;
    let slice = cursor
        .peek_slice(len)
        .map_err(|_| AuthError::Decode)?
        .to_vec();
    cursor.advance(len).map_err(|_| AuthError::Decode)?;
    Ok(slice)
}

/// Encode the OpenSyn body `{user, hmac}` (zenoh writes each as a `ZBuf`).
fn encode_open_syn(user: &[u8], hmac: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(user.len() + hmac.len() + 4);
    encode_vle_u64_into(&mut out, user.len() as u64);
    out.extend_from_slice(user);
    encode_vle_u64_into(&mut out, hmac.len() as u64);
    out.extend_from_slice(hmac);
    out
}

/// Decode the OpenSyn body into `(user, hmac)`.
fn decode_open_syn(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
    let mut cursor = SceCursor::new(bytes);
    let user = read_vle_bytes(&mut cursor)?;
    let hmac = read_vle_bytes(&mut cursor)?;
    Ok((user, hmac))
}

/// The usrpwd auth method — the wz mirror of zenoh `AuthUsrPwd`. A node holds
/// `credentials` to authenticate AS an initiator, and/or a `lookup` table to
/// authenticate peers AS a responder (a node may be both, like zenoh's
/// `AuthUsrPwd { credentials, lookup }`).
pub struct UsrPwdMethod {
    /// Initiator side: this peer's `(user, password)`; `None` = does not
    /// initiate usrpwd.
    credentials: Option<(Vec<u8>, Vec<u8>)>,
    /// Responder side: the `(user, password)` table; empty = does not respond to
    /// usrpwd (a linear scan — auth dictionaries are small + no_std-friendly).
    lookup: Vec<(Vec<u8>, Vec<u8>)>,
    /// Responder side: the challenge nonce sent on InitAck, INJECTED at
    /// construction (no RNG in the no_std core).
    nonce: u64,
    /// Initiator side: the nonce received from the peer's InitAck.
    recv_nonce: Option<u64>,
}

impl UsrPwdMethod {
    /// An INITIATOR-side method authenticating with `(user, password)`.
    pub fn initiator(user: Vec<u8>, password: Vec<u8>) -> Self {
        Self {
            credentials: Some((user, password)),
            lookup: Vec::new(),
            nonce: 0,
            recv_nonce: None,
        }
    }

    /// A RESPONDER-side method with a `(user, password)` `lookup` table and the
    /// challenge `nonce` (INJECTED — the kernel keeps it deterministic +
    /// testable).
    ///
    /// SECURITY CONTRACT (the live-handshake atom MUST honor this): the `nonce`
    /// is the ONLY replay defense — a captured OpenSyn `{user, hmac}` replays
    /// against any responder reusing the same nonce. The live wiring MUST draw a
    /// FRESH cryptographically-random `nonce` PER accepted handshake (the AP
    /// `signing_key_from_os_entropy` / `getrandom` source), never a constant or a
    /// per-process value. A fixed / zero nonce here is a replay hole. usrpwd also
    /// assumes the transport beneath is already encrypted (TLS / QUIC), as zenoh
    /// does — it is not confidential on its own.
    pub fn responder(lookup: Vec<(Vec<u8>, Vec<u8>)>, nonce: u64) -> Self {
        Self {
            credentials: None,
            lookup,
            nonce,
            recv_nonce: None,
        }
    }

    fn password_for(&self, user: &[u8]) -> Option<&[u8]> {
        self.lookup
            .iter()
            .find(|(u, _)| u.as_slice() == user)
            .map(|(_, p)| p.as_slice())
    }
}

impl AuthMethod for UsrPwdMethod {
    fn id(&self) -> u8 {
        USRPWD_ID
    }

    fn open_init_syn(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        // Offer usrpwd iff this node has credentials to present.
        Ok(self.credentials.as_ref().map(|_| AuthSubExt::Unit))
    }

    fn open_recv_init_ack(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        if self.credentials.is_none() {
            return Ok(());
        }
        match sub {
            Some(AuthSubExt::Z64(nonce)) => {
                self.recv_nonce = Some(nonce);
                Ok(())
            }
            _ => Err(AuthError::Rejected("usrpwd: missing InitAck nonce")),
        }
    }

    fn open_open_syn(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        let Some((user, password)) = self.credentials.as_ref() else {
            return Ok(None);
        };
        let nonce = self
            .recv_nonce
            .ok_or(AuthError::Rejected("usrpwd: no nonce for OpenSyn"))?;
        let hmac = hmac_sha3_256(&nonce.to_le_bytes(), password);
        Ok(Some(AuthSubExt::Zbuf(encode_open_syn(user, &hmac))))
    }

    fn open_recv_open_ack(&mut self, _sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        // Receiving the OpenAck means the responder accepted; a denial arrives
        // as a transport Close, not an OpenAck, so there is nothing to check.
        Ok(())
    }

    fn accept_recv_init_syn(&mut self, _sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        // The InitSyn is the open side's usrpwd offer; the challenge nonce is
        // issued on InitAck whenever this node responds (has a lookup table).
        Ok(())
    }

    fn accept_init_ack(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        if self.lookup.is_empty() {
            return Ok(None);
        }
        Ok(Some(AuthSubExt::Z64(self.nonce)))
    }

    fn accept_recv_open_syn(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        if self.lookup.is_empty() {
            return Ok(());
        }
        let Some(AuthSubExt::Zbuf(body)) = sub else {
            return Err(AuthError::Rejected("usrpwd: missing OpenSyn"));
        };
        let (user, hmac) = decode_open_syn(&body)?;
        let password = self
            .password_for(&user)
            .ok_or(AuthError::Rejected("usrpwd: unknown user"))?;
        if !hmac_sha3_256_verify(&self.nonce.to_le_bytes(), password, &hmac) {
            return Err(AuthError::Rejected("usrpwd: bad password"));
        }
        Ok(())
    }

    fn accept_open_ack(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        if self.lookup.is_empty() {
            return Ok(None);
        }
        Ok(Some(AuthSubExt::Unit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_dispatch::AuthDispatch;
    use alloc::boxed::Box;
    use wz_codecs::ext_entry::ExtEntryOwned;

    fn into_exts(ext: Option<ExtEntryOwned>) -> Vec<ExtEntryOwned> {
        ext.into_iter().collect()
    }

    /// Drive the full four-message usrpwd exchange through two dispatches and
    /// return the accept side's verdict (the OpenSyn verify is where a bad
    /// credential surfaces).
    fn run_handshake(initiator: UsrPwdMethod, responder: UsrPwdMethod) -> Result<(), AuthError> {
        let mut open = AuthDispatch::new(alloc::vec![Box::new(initiator) as _]);
        let mut accept = AuthDispatch::new(alloc::vec![Box::new(responder) as _]);

        let init_syn = open.open_init_syn()?;
        accept.accept_recv_init_syn(&into_exts(init_syn))?;
        let init_ack = accept.accept_init_ack()?;
        open.open_recv_init_ack(&into_exts(init_ack))?;
        let open_syn = open.open_open_syn()?;
        accept.accept_recv_open_syn(&into_exts(open_syn))?;
        let open_ack = accept.accept_open_ack()?;
        open.open_recv_open_ack(&into_exts(open_ack))?;
        Ok(())
    }

    #[test]
    fn matching_credentials_authenticate() {
        let r = run_handshake(
            UsrPwdMethod::initiator(b"alice".to_vec(), b"s3cret".to_vec()),
            UsrPwdMethod::responder(
                alloc::vec![(b"alice".to_vec(), b"s3cret".to_vec())],
                0x1234_5678,
            ),
        );
        assert_eq!(r, Ok(()), "matching user/password authenticates");
    }

    #[test]
    fn a_wrong_password_is_rejected() {
        let r = run_handshake(
            UsrPwdMethod::initiator(b"alice".to_vec(), b"wrong".to_vec()),
            UsrPwdMethod::responder(
                alloc::vec![(b"alice".to_vec(), b"s3cret".to_vec())],
                0x1234_5678,
            ),
        );
        assert_eq!(r, Err(AuthError::Rejected("usrpwd: bad password")));
    }

    #[test]
    fn an_unknown_user_is_rejected() {
        let r = run_handshake(
            UsrPwdMethod::initiator(b"mallory".to_vec(), b"s3cret".to_vec()),
            UsrPwdMethod::responder(
                alloc::vec![(b"alice".to_vec(), b"s3cret".to_vec())],
                0x1234_5678,
            ),
        );
        assert_eq!(r, Err(AuthError::Rejected("usrpwd: unknown user")));
    }

    #[test]
    fn open_syn_body_round_trips() {
        let body = encode_open_syn(b"alice", &[0xAB; 32]);
        let (user, hmac) = decode_open_syn(&body).unwrap();
        assert_eq!(user, b"alice");
        assert_eq!(hmac, [0xAB; 32]);
    }

    #[test]
    fn open_syn_body_is_canonical_zenoh_two_zbuf_bytes() {
        // GOLDEN vector: zenoh `Zenoh080` writes {user, hmac} as VLE-len + bytes,
        // twice (usrpwd.rs:241-245). user="alice" (len 5), hmac=0xAB×32 (len 32)
        // — both lengths < 0x80, so single-byte VLE. This pins the exact wire,
        // the unit-level down payment on the wz<->zenohd interop e2e. (Values
        // are < 2^63, so the LEB128-vs-9-byte-cap divergence — tracked in
        // crate::vle — does not arise here.)
        let body = encode_open_syn(b"alice", &[0xAB; 32]);
        let mut expected = alloc::vec![0x05, b'a', b'l', b'i', b'c', b'e', 0x20];
        expected.extend_from_slice(&[0xAB; 32]);
        assert_eq!(
            body, expected,
            "OpenSyn body must be the canonical zenoh two-ZBuf byte sequence"
        );
    }
}

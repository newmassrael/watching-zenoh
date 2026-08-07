// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pubkey auth method (`access-extauth-pubkey`) — the wz mirror of zenoh
//! `establishment/ext/auth/pubkey.rs`. A MUTUAL RSA challenge-response
//! [`AuthMethod`] on the Z_EXT_AUTH dispatch (method id [`id::PUBKEY`] = `0x1`).
//!
//! # Why this lives in `wz-runtime-tokio`, not the no_std session kernel
//!
//! The `rsa` crate requires `std`, so — unlike usrpwd (no_std, in
//! `wz-session-core`) — pubkey is AP-only and lives here. The [`AuthMethod`]
//! trait, the [`AuthDispatch`](wz_session_core::auth_dispatch::AuthDispatch), the
//! [`id`] namespace and the [`read_zbuf`]/[`write_zbuf`] ZBuf codec all stay in
//! the kernel; only the concrete impl lives where its crypto dependency mandates
//! (the clean trait/impl split). It plugs into the SAME method-agnostic dispatch
//! + open seams (`connect_/accept_and_open_session_with_auth`) as usrpwd.
//!
//! # Wire (zenoh-faithful, mutual challenge-response)
//!
//! - InitSyn (initiator->responder) = `Zbuf{ my_pubkey }`
//! - InitAck (responder->initiator) = `Zbuf{ my_pubkey, challenge_enc_with_peer_pubkey }`
//! - OpenSyn (initiator->responder) = `Zbuf{ challenge_reenc_with_peer_pubkey }`
//! - OpenAck (responder->initiator) = `Unit`
//!
//! A public key is two zenoh `ZBuf`s — `n.to_bytes_le()` then `e.to_bytes_le()`
//! (zenoh `ZPublicKey` `WCodec`); a ciphertext is one `ZBuf`. Encryption is
//! PKCS#1 v1.5 ([`Pkcs1v15Encrypt`]); decryption uses [`RsaPrivateKey::decrypt`]'s
//! blinded form. The responder generates a `u64` challenge, encrypts it under the
//! initiator's key; the initiator decrypts it (proving it holds its private key)
//! and RE-encrypts the decrypted bytes VERBATIM under the responder's key (so the
//! initiator never interprets the challenge — opaque-bytes relay, which makes the
//! initiator wire-format-agnostic and cross-impl robust); the responder decrypts
//! and checks the bytes equal `challenge.to_le_bytes()` (zenoh-exact).
//!
//! # Challenge nonce source
//!
//! The responder's `u64` challenge is the per-handshake nonce injected by the
//! accept seam ([`accept_and_open_session_with_auth`](crate::session_open) via
//! [`refresh_auth_challenge_nonce`](wz_session_core::session_actions::SessionLinkActions::refresh_auth_challenge_nonce)
//! -> [`AuthMethod::set_challenge_nonce`]) — the SAME OS-entropy draw usrpwd
//! uses, so both methods share one replay-defense nonce path. The RSA padding +
//! blinding randomness is drawn separately from `OsRng`.
//!
//! # SECURITY (RUSTSEC-2023-0071)
//!
//! The `rsa` crate carries RUSTSEC-2023-0071 (the "Marvin" timing sidechannel on
//! PKCS#1 v1.5 decryption; no fixed version exists). This mirror uses the BLINDED
//! decrypt (zenoh's mitigation) and inherits zenoh's threat model: pubkey assumes
//! the transport beneath is already TLS/QUIC-encrypted and is AP-only — a local
//! decrypt-timing oracle requires an attacker already measuring the AP's RSA
//! timing, which the encrypted-transport assumption bounds. This is the faithful
//! catalog mirror of zenoh's own choice, adopted per an explicit dep decision.

use rand::rngs::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sce_forge_runtime::codec::SceCursor;

use wz_session_core::auth_dispatch::{id, AuthError, AuthMethod, AuthSubExt};
use wz_session_core::vle::{read_zbuf, write_zbuf};

/// Generate a fresh RSA keypair of `bits` size from OS entropy — for ephemeral
/// identities and tests. A persistent deploy instead loads its key from PEM (a
/// config surface deferred until a deploy needs it); zenoh's `key_size` config
/// drives the same `RsaPrivateKey::new`. The public half is `RsaPublicKey::from`.
pub fn generate_keypair(bits: usize) -> Result<RsaPrivateKey, AuthError> {
    RsaPrivateKey::new(&mut OsRng, bits)
        .map_err(|_| AuthError::Rejected("pubkey: key generation failed"))
}

/// Encode an RSA public key as zenoh's `ZPublicKey`: two `ZBuf`s, the modulus
/// `n` then the exponent `e`, each as little-endian bytes (zenoh
/// `BigUint::to_bytes_le`).
fn encode_pubkey(key: &RsaPublicKey) -> Vec<u8> {
    let mut out = Vec::new();
    write_zbuf(&mut out, &key.n().to_bytes_le());
    write_zbuf(&mut out, &key.e().to_bytes_le());
    out
}

/// Read a `ZPublicKey` (two `ZBuf`s, n then e LE) from `cursor`.
fn read_pubkey(cursor: &mut SceCursor<'_>) -> Result<RsaPublicKey, AuthError> {
    let n = read_zbuf(cursor).ok_or(AuthError::Decode)?;
    let e = read_zbuf(cursor).ok_or(AuthError::Decode)?;
    RsaPublicKey::new(BigUint::from_bytes_le(&n), BigUint::from_bytes_le(&e))
        .map_err(|_| AuthError::Rejected("pubkey: invalid RSA public key"))
}

/// Encode the InitSyn body `{ my_pubkey }`.
fn encode_init_syn(key: &RsaPublicKey) -> Vec<u8> {
    encode_pubkey(key)
}

/// Encode the InitAck body `{ my_pubkey, challenge_ciphertext }` (the pubkey's
/// two ZBufs then the ciphertext ZBuf).
fn encode_init_ack(key: &RsaPublicKey, challenge_ct: &[u8]) -> Vec<u8> {
    let mut out = encode_pubkey(key);
    write_zbuf(&mut out, challenge_ct);
    out
}

/// Decode the InitAck body into `(peer_pubkey, challenge_ciphertext)`.
fn decode_init_ack(bytes: &[u8]) -> Result<(RsaPublicKey, Vec<u8>), AuthError> {
    let mut cursor = SceCursor::new(bytes);
    let key = read_pubkey(&mut cursor)?;
    let ct = read_zbuf(&mut cursor).ok_or(AuthError::Decode)?;
    Ok((key, ct))
}

/// Encode the OpenSyn body `{ challenge_ciphertext }` (one ZBuf).
fn encode_open_syn(challenge_ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_zbuf(&mut out, challenge_ct);
    out
}

/// Decode a single-`ZBuf` body (the OpenSyn ciphertext).
fn decode_single_zbuf(bytes: &[u8]) -> Result<Vec<u8>, AuthError> {
    let mut cursor = SceCursor::new(bytes);
    read_zbuf(&mut cursor).ok_or(AuthError::Decode)
}

/// RSA-encrypt `msg` under `key` with PKCS#1 v1.5 padding (zenoh
/// `key.encrypt(prng, Pkcs1v15Encrypt, msg)`).
fn encrypt(key: &RsaPublicKey, msg: &[u8]) -> Result<Vec<u8>, AuthError> {
    let mut rng = OsRng;
    key.encrypt(&mut rng, Pkcs1v15Encrypt, msg)
        .map_err(|_| AuthError::Rejected("pubkey: encryption error"))
}

/// RSA-decrypt `ct` with `key` (the BLINDED form — zenoh `decrypt_blinded`, the
/// RUSTSEC-2023-0071 timing mitigation).
fn decrypt_blinded(key: &RsaPrivateKey, ct: &[u8]) -> Result<Vec<u8>, AuthError> {
    let mut rng = OsRng;
    key.decrypt_blinded(&mut rng, Pkcs1v15Encrypt, ct)
        .map_err(|_| AuthError::Rejected("pubkey: decryption error"))
}

/// The pubkey auth method — the wz mirror of zenoh `AuthPubKey`. A node holds its
/// RSA keypair (it proves its identity by decrypting the peer's challenge) and,
/// as a responder, an optional `lookup` of accepted initiator public keys.
pub struct PubKeyMethod {
    /// This node's RSA private key — decrypts challenges to prove key ownership.
    private_key: RsaPrivateKey,
    /// This node's RSA public key (sent on InitSyn / InitAck).
    public_key: RsaPublicKey,
    /// The accepted-peer-key policy, modelling zenoh's
    /// `Option<HashSet<ZPublicKey>>` (`AuthPubKey.lookup`). zenoh carries ONE such
    /// field per authenticator and consults it on BOTH sides of the handshake —
    /// but under TWO DIFFERENT RULES, and the difference is load-bearing:
    /// - RESPONDER (`recv_init_syn`, pubkey.rs:566-570) — `None` accepts any
    ///   initiator key; `Some(set)` requires membership, so a `Some(empty)`
    ///   rejects EVERY key. See [`PubKeyMethod::admits_initiator`].
    /// - INITIATOR (`recv_init_ack`, pubkey.rs:414-418) — the same `None`, but the
    ///   membership test is guarded by `!lookup.is_empty()`, so a `Some(empty)`
    ///   accepts ANY responder key. See [`PubKeyMethod::admits_responder`].
    ///
    /// R311y576 built the initiator half; before it, wz stored this field and read
    /// it on the responder side only, so a wz initiator admitted any responder key
    /// whatever its caller configured. The asymmetry is not a wz reading of the
    /// prose: a stock pubkey zenohd's lookup IS `Some(empty)`, and it completes a
    /// handshake it DIALS while rejecting every handshake it accepts — measured in
    /// `pubkey_zenohd_interop.rs`, both directions.
    ///
    /// The `Vec` (rather than a bare "empty = accept any") is a DELIBERATE choice
    /// in the same direction: a `responder(key, vec![])` meant as lockdown must not
    /// silently admit everyone. zenoh's own config path can only ever build
    /// `Some(empty)` (its `known_keys_file` loader is an unimplemented `@TODO` at
    /// pubkey.rs:122), which is exactly why a stock pubkey zenohd rejects all
    /// clients that dial it.
    lookup: Option<Vec<RsaPublicKey>>,
    /// Responder side: the per-handshake `u64` challenge, injected via
    /// [`AuthMethod::set_challenge_nonce`] (the accept seam's OS-entropy draw --
    /// the SAME shared nonce path usrpwd uses; only the RSA padding/blinding
    /// randomness is drawn locally from `OsRng`, never a second challenge source).
    challenge: u64,
    /// Responder side: the initiator's public key captured on InitSyn.
    peer_pubkey: Option<RsaPublicKey>,
    /// Initiator side: the responder's public key captured on InitAck.
    resp_pubkey: Option<RsaPublicKey>,
    /// Initiator side: the DECRYPTED challenge bytes (opaque) to re-encrypt on
    /// OpenSyn. Never interpreted — relayed verbatim.
    decrypted_challenge: Option<Vec<u8>>,
}

impl PubKeyMethod {
    /// An INITIATOR-side method authenticating with `private_key`. It offers its
    /// public key on InitSyn and proves possession by decrypting + relaying the
    /// responder's challenge. It carries NO accepted-responder-key set, so it
    /// admits whichever key answers — zenoh's `disable_lookup` semantic on the
    /// initiator side. To gate the responder's key, use
    /// [`PubKeyMethod::initiator_with_lookup`].
    pub fn initiator(private_key: RsaPrivateKey) -> Self {
        Self::initiator_with_lookup(private_key, None)
    }

    /// An INITIATOR-side method that also GATES the responder's public key, the
    /// mirror of [`PubKeyMethod::responder`]'s initiator gating: `None` admits any
    /// responder key, `Some(set)` requires membership — EXCEPT that a
    /// `Some(empty)` admits any key, because zenoh's initiator check is guarded by
    /// `!lookup.is_empty()` where its responder check is not
    /// (`io/zenoh-transport/src/unicast/establishment/ext/auth/pubkey.rs:414-418`
    /// versus `:566-570`, zenoh 1.5.0). Carrying that asymmetry rather than
    /// reusing the responder rule is what lets a wz responder complete a handshake
    /// a stock zenohd DIALS: zenohd's own lookup is `Some(empty)`.
    ///
    /// Until R311y576 this constructor did not exist and the gate was unbuilt, so
    /// a wz initiator relayed the challenge to, and completed a session with, any
    /// responder that answered. The doc on [`PubKeyMethod::initiator`] recorded it
    /// as a residual for 136 rounds.
    pub fn initiator_with_lookup(
        private_key: RsaPrivateKey,
        lookup: Option<Vec<RsaPublicKey>>,
    ) -> Self {
        let public_key = RsaPublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
            lookup,
            challenge: 0,
            peer_pubkey: None,
            resp_pubkey: None,
            decrypted_challenge: None,
        }
    }

    /// A RESPONDER-side method with `private_key` and an accepted-initiator-key
    /// policy: `None` accepts any key (zenoh `disable_lookup`); `Some(set)`
    /// requires membership — a `Some(empty)` rejects ALL (zenoh-faithful). The
    /// per-handshake challenge is injected via
    /// [`AuthMethod::set_challenge_nonce`] (the accept seam draws a fresh one from
    /// OS entropy) — a fixed / reused challenge is a replay hole.
    pub fn responder(private_key: RsaPrivateKey, lookup: Option<Vec<RsaPublicKey>>) -> Self {
        let public_key = RsaPublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
            lookup,
            challenge: 0,
            peer_pubkey: None,
            resp_pubkey: None,
            decrypted_challenge: None,
        }
    }

    /// Whether this RESPONDER admits the initiator key `peer`. Mirrors zenoh
    /// `recv_init_syn`'s `if let Some(lookup) { contains }` (pubkey.rs:566-570):
    /// `None` accepts any key; `Some(set)` requires membership, so an empty `Some`
    /// rejects all.
    fn admits_initiator(&self, peer: &RsaPublicKey) -> bool {
        match &self.lookup {
            None => true,
            Some(set) => set.iter().any(|k| k == peer),
        }
    }

    /// Whether this INITIATOR admits the responder key `peer`. Mirrors zenoh
    /// `recv_init_ack`'s `if !lookup.is_empty() && !lookup.contains(..)`
    /// (pubkey.rs:414-418) — the SAME field as [`Self::admits_initiator`] under a
    /// DIFFERENT rule: an empty `Some` accepts every key here, where on the
    /// responder side it rejects every key.
    ///
    /// The divergence is upstream's, not wz's, and it is the reason a stock
    /// zenohd (whose lookup is `Some(empty)`, `AuthPubKey::new` at pubkey.rs:54-61)
    /// can dial into an authenticated session while admitting nobody who dials it.
    /// Collapsing the two rules onto one would silently break that direction.
    fn admits_responder(&self, peer: &RsaPublicKey) -> bool {
        match &self.lookup {
            None => true,
            Some(set) => set.is_empty() || set.iter().any(|k| k == peer),
        }
    }
}

impl AuthMethod for PubKeyMethod {
    fn id(&self) -> u8 {
        id::PUBKEY
    }

    fn set_challenge_nonce(&mut self, nonce: u64) {
        self.challenge = nonce;
    }

    // ── Open (initiator) side ────────────────────────────────────────────
    fn open_init_syn(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        // Offer this node's public key — the initiator always presents it.
        Ok(Some(AuthSubExt::Zbuf(encode_init_syn(&self.public_key))))
    }

    fn open_recv_init_ack(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        let Some(AuthSubExt::Zbuf(body)) = sub else {
            return Err(AuthError::Rejected("pubkey: missing InitAck"));
        };
        let (resp_pubkey, challenge_ct) = decode_init_ack(&body)?;
        // Gate the RESPONDER's key BEFORE spending a decryption on its challenge —
        // zenoh checks the lookup at pubkey.rs:414-418, above the `decrypt_blinded`
        // at `:419-427`. The order is observable: an unauthorized key whose
        // ciphertext is also malformed must report unauthorized, not a decode
        // failure, or the reject reason leaks which check ran first.
        if !self.admits_responder(&resp_pubkey) {
            return Err(AuthError::Rejected("pubkey: unauthorized responder key"));
        }
        // Decrypt the responder's challenge with OUR private key — proves we hold
        // it. Keep the bytes OPAQUE (relay verbatim; never interpreted).
        let decrypted = decrypt_blinded(&self.private_key, &challenge_ct)?;
        self.resp_pubkey = Some(resp_pubkey);
        self.decrypted_challenge = Some(decrypted);
        Ok(())
    }

    fn open_open_syn(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        let (Some(resp_pubkey), Some(decrypted)) =
            (self.resp_pubkey.as_ref(), self.decrypted_challenge.as_ref())
        else {
            return Ok(None);
        };
        // Re-encrypt the decrypted challenge under the RESPONDER's key.
        let reenc = encrypt(resp_pubkey, decrypted)?;
        Ok(Some(AuthSubExt::Zbuf(encode_open_syn(&reenc))))
    }

    fn open_recv_open_ack(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        // zenoh's pubkey initiator REQUIRES the responder's OpenAck Unit
        // confirmation (pubkey.rs:471 bails on its absence) — it is the
        // initiator's assurance that the responder ran pubkey to completion. A
        // denial instead arrives as a transport Close. (usrpwd's OpenAck is
        // genuinely unchecked in zenoh, hence the divergence is pubkey-only.)
        match sub {
            Some(AuthSubExt::Unit) => Ok(()),
            _ => Err(AuthError::Rejected("pubkey: missing OpenAck")),
        }
    }

    // ── Accept (responder) side ──────────────────────────────────────────
    fn accept_recv_init_syn(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        // A pubkey RESPONDER REQUIRES the initiator to present its public key on
        // InitSyn (zenoh pubkey.rs:558 bails "Missing PubKey extension"). The
        // accept_* stages run ONLY on the accept side, so a method reaching here
        // is acting as a responder — a missing or malformed offer is a reject,
        // not a silent bypass of pubkey auth.
        let Some(AuthSubExt::Zbuf(body)) = sub else {
            return Err(AuthError::Rejected("pubkey: missing InitSyn offer"));
        };
        let mut cursor = SceCursor::new(&body);
        let peer = read_pubkey(&mut cursor)?;
        if !self.admits_initiator(&peer) {
            return Err(AuthError::Rejected("pubkey: unauthorized public key"));
        }
        self.peer_pubkey = Some(peer);
        Ok(())
    }

    fn accept_init_ack(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        let Some(peer) = self.peer_pubkey.as_ref() else {
            return Ok(None);
        };
        // Challenge = the injected per-handshake nonce, encrypted under the
        // initiator's key (only the holder of its private key can decrypt it).
        let challenge_ct = encrypt(peer, &self.challenge.to_le_bytes())?;
        Ok(Some(AuthSubExt::Zbuf(encode_init_ack(
            &self.public_key,
            &challenge_ct,
        ))))
    }

    fn accept_recv_open_syn(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        if self.peer_pubkey.is_none() {
            return Ok(());
        }
        let Some(AuthSubExt::Zbuf(body)) = sub else {
            return Err(AuthError::Rejected("pubkey: missing OpenSyn"));
        };
        let reenc = decode_single_zbuf(&body)?;
        // Decrypt the re-encrypted challenge with OUR private key; it must equal
        // the challenge we issued (zenoh-exact `u64.to_le_bytes()` compare).
        let recovered = decrypt_blinded(&self.private_key, &reenc)?;
        if recovered != self.challenge.to_le_bytes() {
            return Err(AuthError::Rejected("pubkey: invalid nonce"));
        }
        Ok(())
    }

    fn accept_open_ack(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        if self.peer_pubkey.is_none() {
            return Ok(None);
        }
        Ok(Some(AuthSubExt::Unit))
    }

    /// R311y205 (transport-multilink IMPL-2b-ii) — the peer's captured ephemeral
    /// key in its canonical encoded ZPublicKey form. The RESPONDER captures the
    /// initiator's key on InitSyn (`peer_pubkey`), the INITIATOR captures the
    /// responder's key on InitAck (`resp_pubkey`); either side surfaces whichever
    /// it holds. Re-encodes through the SAME [`encode_pubkey`] the InitSyn body
    /// uses, so the bytes are identical to the on-wire form the peer sent — a
    /// byte-equality on the encoded key across two links proves they present the
    /// SAME ephemeral identity (the multilink join's config-equality gate).
    fn captured_peer_key_bytes(&self) -> Option<Vec<u8>> {
        self.peer_pubkey
            .as_ref()
            .or(self.resp_pubkey.as_ref())
            .map(encode_pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_codecs::ext_entry::ExtEntryOwned;
    use wz_session_core::auth_dispatch::AuthDispatch;

    /// A fresh 512-bit RSA keypair — small for test speed (the wire is
    /// key-size-agnostic; production keys are 2048+).
    fn keypair() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut OsRng, 512).expect("512-bit test RSA key")
    }

    fn into_exts(ext: Option<ExtEntryOwned>) -> Vec<ExtEntryOwned> {
        ext.into_iter().collect()
    }

    /// Drive the full four-message mutual pubkey exchange through two dispatches
    /// (so it exercises the real mux/demux + ext-chain codec, not just the method
    /// methods) and return the responder's verdict. The responder challenge is
    /// injected via the dispatch (the accept-seam path).
    fn run_handshake(
        initiator: PubKeyMethod,
        responder: PubKeyMethod,
        challenge: u64,
    ) -> Result<(), AuthError> {
        let mut open = AuthDispatch::new(vec![Box::new(initiator) as _]);
        let mut accept = AuthDispatch::new(vec![Box::new(responder) as _]);
        accept.set_challenge_nonce(challenge);

        let init_syn = open.open_init_syn().unwrap();
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
    fn mutual_auth_round_trip_authenticates() {
        let init = keypair();
        let init_pub = RsaPublicKey::from(&init);
        let r = run_handshake(
            PubKeyMethod::initiator(init),
            PubKeyMethod::responder(keypair(), Some(vec![init_pub])),
            0x1122_3344_5566_7788,
        );
        assert_eq!(
            r,
            Ok(()),
            "matching keys authenticate the challenge round-trip"
        );
    }

    #[test]
    fn none_lookup_accepts_any_initiator_key() {
        // `None` lookup = accept any (zenoh's `disable_lookup` semantic).
        let r = run_handshake(
            PubKeyMethod::initiator(keypair()),
            PubKeyMethod::responder(keypair(), None),
            0x42,
        );
        assert_eq!(r, Ok(()), "a None lookup admits any initiator key");
    }

    #[test]
    fn some_empty_lookup_rejects_all() {
        // `Some(empty)` = membership required over an empty set = reject ALL.
        // This is zenoh-faithful (recv_init_syn bails on `!lookup.contains`), and
        // the safe direction: `responder(key, Some(vec![]))` meant as lockdown
        // admits nobody (a bare-Vec "empty = accept any" would silently admit all).
        let r = run_handshake(
            PubKeyMethod::initiator(keypair()),
            PubKeyMethod::responder(keypair(), Some(Vec::new())),
            0x42,
        );
        assert_eq!(
            r,
            Err(AuthError::Rejected("pubkey: unauthorized public key")),
            "an empty Some-lookup rejects every initiator (zenoh parity)"
        );
    }

    #[test]
    fn unauthorized_initiator_key_is_rejected() {
        // The responder's lookup holds some OTHER key, not the initiator's.
        let other = RsaPublicKey::from(&keypair());
        let r = run_handshake(
            PubKeyMethod::initiator(keypair()),
            PubKeyMethod::responder(keypair(), Some(vec![other])),
            0x42,
        );
        assert_eq!(
            r,
            Err(AuthError::Rejected("pubkey: unauthorized public key"))
        );
    }

    // ── R311y576: the INITIATOR-side lookup gate ─────────────────────────
    //
    // Four tests over one axis. Before y576 the initiator carried no gate at
    // all, so `an_unauthorized_responder_key_is_rejected` is the plane's
    // existence proof and the other three pin its exact shape — in particular
    // that the empty set means the OPPOSITE of what it means on the responder
    // side, which is the one thing a reimplementation gets wrong by symmetry.

    #[test]
    fn an_unauthorized_responder_key_is_rejected_by_the_initiator() {
        // The initiator's lookup holds some OTHER key, not the responder's, so
        // the handshake must die at the initiator's InitAck check — zenoh
        // `recv_init_ack` bails "Unauthorized PubKey" (pubkey.rs:414-418).
        let init = keypair();
        let init_pub = RsaPublicKey::from(&init);
        let unrelated = RsaPublicKey::from(&keypair());
        let r = run_handshake(
            PubKeyMethod::initiator_with_lookup(init, Some(vec![unrelated])),
            // The RESPONDER admits this initiator, so the only check that can
            // reject is the new initiator-side one.
            PubKeyMethod::responder(keypair(), Some(vec![init_pub])),
            0x42,
        );
        assert_eq!(
            r,
            Err(AuthError::Rejected("pubkey: unauthorized responder key")),
            "an initiator carrying a non-empty lookup must reject a responder \
             key outside it"
        );
    }

    #[test]
    fn an_authorized_responder_key_is_admitted_by_the_initiator() {
        // The positive arm the test above needs to mean anything: the SAME
        // shape with the responder's real key in the lookup authenticates.
        let init = keypair();
        let init_pub = RsaPublicKey::from(&init);
        let resp = keypair();
        let resp_pub = RsaPublicKey::from(&resp);
        let r = run_handshake(
            PubKeyMethod::initiator_with_lookup(init, Some(vec![resp_pub])),
            PubKeyMethod::responder(resp, Some(vec![init_pub])),
            0x42,
        );
        assert_eq!(r, Ok(()), "membership admits the responder key");
    }

    #[test]
    fn some_empty_lookup_admits_any_responder_key() {
        // THE DISCRIMINATOR between the two rules, and the reason they are two
        // functions. The same `Some(vec![])` that makes a RESPONDER reject
        // every initiator (`some_empty_lookup_rejects_all`, above) makes an
        // INITIATOR admit every responder, because zenoh guards the initiator's
        // membership test with `!lookup.is_empty()` (pubkey.rs:415) and does not
        // guard the responder's (pubkey.rs:567).
        //
        // This is not a wz reading of upstream prose. A stock zenohd's lookup IS
        // `Some(empty)` (`AuthPubKey::new`, pubkey.rs:54-61) and it completes a
        // pubkey handshake it DIALS while rejecting every one it accepts — both
        // directions measured against the real router in
        // `wz-integration-tests/tests/pubkey_zenohd_interop.rs`.
        let init = keypair();
        let init_pub = RsaPublicKey::from(&init);
        let r = run_handshake(
            PubKeyMethod::initiator_with_lookup(init, Some(Vec::new())),
            PubKeyMethod::responder(keypair(), Some(vec![init_pub])),
            0x42,
        );
        assert_eq!(
            r,
            Ok(()),
            "an EMPTY Some-lookup admits every responder key — the inverse of \
             the responder-side rule, and zenoh-faithful"
        );
    }

    #[test]
    fn the_initiator_gate_runs_before_the_challenge_decryption() {
        // ORDER, not just outcome. zenoh checks the lookup at pubkey.rs:414-418
        // and decrypts at `:419-427`. Hand the initiator an InitAck whose key is
        // unauthorized AND whose ciphertext is garbage that cannot decrypt: if
        // the gate runs first the verdict is "unauthorized responder key", if it
        // runs second it is "decryption error". A gate placed after the decrypt
        // would still reject this handshake, so outcome alone cannot see the
        // difference and only the reason string can.
        let init = keypair();
        let unrelated = RsaPublicKey::from(&keypair());
        let mut initiator = PubKeyMethod::initiator_with_lookup(init, Some(vec![unrelated]));
        let stranger = RsaPublicKey::from(&keypair());
        let body = encode_init_ack(&stranger, b"not a valid RSA ciphertext");
        assert_eq!(
            initiator.open_recv_init_ack(Some(AuthSubExt::Zbuf(body))),
            Err(AuthError::Rejected("pubkey: unauthorized responder key")),
            "the lookup must be consulted BEFORE the challenge decryption"
        );
    }

    #[test]
    fn a_mismatched_challenge_response_is_rejected() {
        // The responder issues a challenge for 0xAAAA but is handed an OpenSyn
        // that re-encrypts a DIFFERENT value (0xBBBB) — the decrypt succeeds but
        // the recovered bytes do not equal the issued challenge. Driven at the
        // method level so the forged OpenSyn is exact.
        let resp_priv = keypair();
        let resp_pub = RsaPublicKey::from(&resp_priv);
        let init_pub = RsaPublicKey::from(&keypair());
        let mut responder = PubKeyMethod::responder(resp_priv, Some(vec![init_pub.clone()]));
        responder.set_challenge_nonce(0xAAAA);
        responder
            .accept_recv_init_syn(Some(AuthSubExt::Zbuf(encode_init_syn(&init_pub))))
            .unwrap();
        let _challenge = responder.accept_init_ack().unwrap();
        let wrong = encrypt(&resp_pub, &0xBBBB_u64.to_le_bytes()).unwrap();
        let forged = Some(AuthSubExt::Zbuf(encode_open_syn(&wrong)));
        assert_eq!(
            responder.accept_recv_open_syn(forged),
            Err(AuthError::Rejected("pubkey: invalid nonce"))
        );
    }

    #[test]
    fn pubkey_codec_round_trips() {
        let key = RsaPublicKey::from(&keypair());
        let bytes = encode_pubkey(&key);
        let mut cursor = SceCursor::new(&bytes);
        let decoded = read_pubkey(&mut cursor).expect("ZPublicKey round-trips");
        assert_eq!(decoded, key, "n + e survive the two-ZBuf LE encoding");
        assert_eq!(cursor.remaining(), 0, "both ZBufs consumed exactly");
    }

    #[test]
    fn a_responder_rejects_an_initsyn_without_the_pubkey_offer() {
        // The accept side REQUIRES the initiator to present its key — a missing
        // offer is a reject, not a silent bypass (zenoh pubkey.rs:558).
        let mut responder = PubKeyMethod::responder(keypair(), None);
        assert_eq!(
            responder.accept_recv_init_syn(None),
            Err(AuthError::Rejected("pubkey: missing InitSyn offer"))
        );
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use alloc::boxed::Box;
use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sce_forge_runtime::codec::SceCursor;
use sha3::Sha3_256;

use crate::auth_dispatch::{id, AuthError, AuthIdentity, AuthMethod, AuthSubExt};
use crate::vle::{read_zbuf, write_zbuf};

/// A fixed dummy password the unknown-user reject path HMACs over so its cost
/// matches a known user's verify (the timing-oracle close in
/// [`UsrPwdMethod::accept_recv_open_syn`]). The value is irrelevant — only the
/// constant HMAC work matters; the verdict is always reject.
const UNKNOWN_USER_DUMMY_PWD: &[u8] = b"wz-usrpwd-unknown-user-dummy";

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

/// Encode the OpenSyn body `{user, hmac}` — two zenoh `ZBuf`s, via the
/// [`crate::vle`] `write_zbuf` SSOT (shared with the pubkey method's body codec).
fn encode_open_syn(user: &[u8], hmac: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(user.len() + hmac.len() + 4);
    write_zbuf(&mut out, user);
    write_zbuf(&mut out, hmac);
    out
}

/// Decode the OpenSyn body into `(user, hmac)` via the `read_zbuf` SSOT.
fn decode_open_syn(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
    let mut cursor = SceCursor::new(bytes);
    let user = read_zbuf(&mut cursor).ok_or(AuthError::Decode)?;
    let hmac = read_zbuf(&mut cursor).ok_or(AuthError::Decode)?;
    Ok((user, hmac))
}

/// Where a responder's `(user, password)` table LIVES — the seam that lets the
/// table be SHARED and MUTATED while this `no_std` core stays ignorant of locks.
///
/// R2567. wz previously had no such seam: `UsrPwdMethod` OWNED its table by
/// value, so every session got a private copy and runtime mutation was not
/// expressible at all. zenoh's per-handshake FSM instead holds a REFERENCE to a
/// shared store (`io/zenoh-transport/src/unicast/establishment/ext/auth/usrpwd.rs`
///  @ `inner: &'a RwLock<AuthUsrPwd>`), which is precisely why its `add_user` /
/// `del_user` take effect. Both of this atom's remaining residuals -- the config
/// dictionary and runtime user mutation -- were consequences of that absence.
///
/// ⚠ THE ACCESSOR IS A CALLBACK, NOT A GETTER, AND THAT IS A SECURITY CHOICE.
/// A `-> Option<Vec<u8>>` would copy a password into a fresh, un-zeroized heap
/// buffer on every handshake -- strictly worse exposure than the borrow it
/// replaces. Upstream does not do that either: it takes its read lock and passes
/// the BORROWED password straight to `hmac::sign`, owning only the username,
/// which is public. Lending under the lock is the shape that matches.
///
/// ⚠⚠ AND IT IS SYNCHRONOUS ON PURPOSE. Upstream's `recv_open_syn` is `async`
/// and takes an async lock, but [`AuthMethod::accept_recv_open_syn`] is a sync
/// trait method; following upstream here would force the whole auth plane async
/// for one lookup. The runtime abstraction already offers exactly this shape --
/// `wz_runtime_core`'s `with_mutex_mut` is a synchronous scoped callback -- so a
/// runtime store implements this trait by lending through it.
pub trait CredentialSource: Send {
    /// Lend the password registered for `user`, if any, to `f`.
    ///
    /// Returns `f`'s value, or `None` when the user is unknown. The password
    /// must not escape `f`: implementations may be holding a lock for exactly
    /// as long as this call.
    fn with_password_for(&self, user: &[u8], f: &mut dyn FnMut(&[u8]) -> bool) -> Option<bool>;
}

/// An in-memory `(user, password)` table — the source a caller-supplied `Vec`
/// becomes, and the only one this `no_std` core provides.
///
/// A linear scan: auth dictionaries are small and this keeps the core free of
/// hashing, exactly as the owned table it replaces did.
pub struct InMemoryCredentials(CredentialTable);

impl InMemoryCredentials {
    pub fn new(table: CredentialTable) -> Self {
        Self(table)
    }
}

impl CredentialSource for InMemoryCredentials {
    fn with_password_for(&self, user: &[u8], f: &mut dyn FnMut(&[u8]) -> bool) -> Option<bool> {
        self.0
            .iter()
            .find(|(u, _)| u.as_slice() == user)
            .map(|(_, p)| f(p.as_slice()))
    }
}

/// A responder's `(user, password)` table.
///
/// R2567 — named because three signatures carry it and clippy is right that the
/// bare tuple-vector reads poorly. Bytes rather than `String` for the reason
/// [`AuthIdentity`](crate::auth_dispatch::AuthIdentity) gives: this is what the
/// wire and the dictionary file supply, and demanding UTF-8 here would invent a
/// validation upstream does not perform at this layer.
pub type CredentialTable = Vec<(Vec<u8>, Vec<u8>)>;

/// Why a dictionary line was refused. Upstream bails the whole load on any of
/// these rather than skipping the line, and so does this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DictionaryError {
    /// No `:` on the line — upstream: "invalid format".
    MissingSeparator,
    /// Empty user before the `:`.
    EmptyUser,
    /// Empty password after the `:`.
    EmptyPassword,
}

/// Parse a `user:password` dictionary into a credential table.
///
/// R2567, residual 2's PURE half. Upstream reads the file with `tokio::fs` and
/// parses it in the same function; this core is `no_std`-shaped and must not
/// grow file I/O, so only the parse lives here and the runtime does the read.
/// That split is also what makes the rules testable without a filesystem.
///
/// THE RULES ARE UPSTREAM'S, taken from its code and pinned by its own tests
/// (`usrpwd.rs` @ `async fn from_config`):
/// * one `<user>:<password>` per line, each line trimmed;
/// * blank lines skipped;
/// * split on the FIRST `:`, so a PASSWORD may legally contain one;
/// * an absent separator, an empty user, or an empty password fails the WHOLE
///   load — upstream bails rather than skipping the line, and a dictionary that
///   silently dropped a malformed entry would authenticate fewer users than its
///   operator believes.
pub fn parse_dictionary(text: &str) -> Result<CredentialTable, DictionaryError> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let idx = line.find(':').ok_or(DictionaryError::MissingSeparator)?;
        let user = line[..idx].trim();
        if user.is_empty() {
            return Err(DictionaryError::EmptyUser);
        }
        let password = line[idx + 1..].trim();
        if password.is_empty() {
            return Err(DictionaryError::EmptyPassword);
        }
        out.push((user.as_bytes().to_vec(), password.as_bytes().to_vec()));
    }
    Ok(out)
}

/// The usrpwd auth method — the wz mirror of zenoh `AuthUsrPwd`. A node holds
/// `credentials` to authenticate AS an initiator, and/or a credential SOURCE to
/// authenticate peers AS a responder (a node may be both, like zenoh's
/// `AuthUsrPwd { credentials, lookup }`).
pub struct UsrPwdMethod {
    /// Initiator side: this peer's `(user, password)`; `None` = does not
    /// initiate usrpwd.
    credentials: Option<(Vec<u8>, Vec<u8>)>,
    /// Responder side: where the `(user, password)` table lives; `None` = does
    /// not respond to usrpwd.
    ///
    /// R2567 — this was `Vec<(Vec<u8>, Vec<u8>)>` and its EMPTINESS was the
    /// sentinel for "not a responder", read at four sites. `Option` makes that
    /// a type instead of a length, and lets the table be shared rather than
    /// copied per session. ⚠ An EMPTY table must still fold to `None`, or an
    /// unconfigured responder silently inverts into one that rejects everybody;
    /// upstream agrees, its `from_config` returns `None` in exactly that case.
    source: Option<Box<dyn CredentialSource>>,
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
            source: None,
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
    ///
    /// ⚠ R2567 — an EMPTY `lookup` folds to NO SOURCE, preserving the exact
    /// meaning the empty-vec sentinel carried before. Wrapping it in a source
    /// instead would turn "not configured as a responder" into "a responder
    /// with zero users", i.e. one that rejects every peer — a silent inversion
    /// of an authentication default that compiles and type-checks. Upstream
    /// folds the same way: `from_config` yields `None`, not an empty table.
    pub fn responder(lookup: CredentialTable, nonce: u64) -> Self {
        match lookup.is_empty() {
            true => Self {
                credentials: None,
                source: None,
                nonce,
                recv_nonce: None,
            },
            false => Self::responder_with_source(Box::new(InMemoryCredentials::new(lookup)), nonce),
        }
    }

    /// A RESPONDER-side method reading a SHARED credential source.
    ///
    /// R2567 — the constructor residuals 2 and 3 need: the store outlives this
    /// method and can be mutated (`add_user` / `del_user`) or loaded from a
    /// dictionary file by the runtime, while each session's method merely
    /// BORROWS through it. That is zenoh's arrangement, where the FSM holds
    /// `&RwLock<AuthUsrPwd>` rather than a copy.
    pub fn responder_with_source(source: Box<dyn CredentialSource>, nonce: u64) -> Self {
        Self {
            credentials: None,
            source: Some(source),
            nonce,
            recv_nonce: None,
        }
    }

    /// Lend the password for `user` to `f`, or `None` when unknown / no source.
    fn with_password_for(&self, user: &[u8], f: &mut dyn FnMut(&[u8]) -> bool) -> Option<bool> {
        self.source.as_ref()?.with_password_for(user, f)
    }
}

impl AuthMethod for UsrPwdMethod {
    fn id(&self) -> u8 {
        id::USRPWD
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

    fn accept_recv_init_syn(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        // A configured usrpwd RESPONDER (a non-empty lookup) REQUIRES the
        // initiator to OFFER usrpwd on InitSyn (the Unit marker) — zenoh
        // usrpwd.rs:372 bails "Expected extension" when configured and the offer
        // is absent. Without this, a peer presenting no usrpwd ext would silently
        // bypass usrpwd auth. The challenge itself is issued on InitAck.
        if self.source.is_some() && sub.is_none() {
            return Err(AuthError::Rejected("usrpwd: missing InitSyn offer"));
        }
        Ok(())
    }

    fn accept_init_ack(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        if self.source.is_none() {
            return Ok(None);
        }
        Ok(Some(AuthSubExt::Z64(self.nonce)))
    }

    fn accept_recv_open_syn(
        &mut self,
        sub: Option<AuthSubExt>,
    ) -> Result<Option<AuthIdentity>, AuthError> {
        if self.source.is_none() {
            // An initiator-role method authenticates nobody on this side.
            return Ok(None);
        }
        let Some(AuthSubExt::Zbuf(body)) = sub else {
            return Err(AuthError::Rejected("usrpwd: missing OpenSyn"));
        };
        let (user, hmac) = decode_open_syn(&body)?;
        let key = self.nonce.to_le_bytes();
        // R3b timing-oracle close (the hardening the R311wy security contract
        // deferred to this live atom): on an UNKNOWN user, run a dummy HMAC
        // over a fixed secret before rejecting, so the reject path costs the
        // same whether or not the username exists. zenoh usrpwd.rs:418
        // early-returns on the lookup miss (a username-enumeration timing
        // oracle); wz hardens beyond it with IDENTICAL wire (both reject the
        // handshake — the difference is only timing, observable solely over a
        // real network, which usrpwd already assumes is TLS/QUIC-encrypted).
        //
        // R2567 — the password is BORROWED for the length of the verify and
        // never copied out. `with_password_for` lends it under whatever lock the
        // source holds, so a shared runtime store can back this without the
        // secret ever landing in a fresh, un-zeroized buffer. zenoh does the
        // same: it takes its read lock and hands the borrowed password straight
        // to `hmac::sign`, owning only the username.
        let mut verified = false;
        let found = self.with_password_for(&user, &mut |password| {
            verified = hmac_sha3_256_verify(&key, password, &hmac);
            verified
        });
        match found {
            Some(_) => {
                if !verified {
                    return Err(AuthError::Rejected("usrpwd: bad password"));
                }
                // R2566 — the username is RETURNED, not dropped. It is
                // authenticated exactly here and nowhere later: past this
                // point the credential is gone and no layer can re-derive who
                // the peer is. zenoh carries the same value out of the same
                // stage as `UsrPwdId(Some(username))`, and it is what feeds the
                // ACL username subject, which is why `access-acl`'s Subject gap
                // was rooted in this function rather than at the ACL layer.
                Ok(Some(AuthIdentity(user)))
            }
            None => {
                // Discarded — the verdict is fixed (reject); only the work
                // matters, equalising the unknown-user branch's HMAC cost.
                let _ = hmac_sha3_256_verify(&key, UNKNOWN_USER_DUMMY_PWD, &hmac);
                Err(AuthError::Rejected("usrpwd: unknown user"))
            }
        }
    }

    fn accept_open_ack(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        if self.source.is_none() {
            return Ok(None);
        }
        Ok(Some(AuthSubExt::Unit))
    }

    fn set_challenge_nonce(&mut self, nonce: u64) {
        // Responder side: this is the InitAck challenge + the OpenSyn-verify
        // key. The live handshake wiring calls this with a FRESH OS-entropy
        // nonce per accepted handshake (the replay-defense contract on
        // [`Self::responder`]). Harmless on an initiator-only method — the
        // initiator reads `recv_nonce`, never this slot.
        self.nonce = nonce;
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
    /// credential surfaces) TOGETHER WITH the identity it authenticated.
    ///
    /// R2566 widened the return: the OpenSyn stage is the only point at which
    /// anyone knows who the peer is, so a helper that dropped it could not tell
    /// "authenticated alice" from "authenticated somebody".
    fn run_handshake(
        initiator: UsrPwdMethod,
        responder: UsrPwdMethod,
    ) -> Result<Option<AuthIdentity>, AuthError> {
        let mut open = AuthDispatch::new(alloc::vec![Box::new(initiator) as _]);
        let mut accept = AuthDispatch::new(alloc::vec![Box::new(responder) as _]);

        let init_syn = open.open_init_syn()?;
        accept.accept_recv_init_syn(&into_exts(init_syn))?;
        let init_ack = accept.accept_init_ack()?;
        open.open_recv_init_ack(&into_exts(init_ack))?;
        let open_syn = open.open_open_syn()?;
        let who = accept.accept_recv_open_syn(&into_exts(open_syn))?;
        let open_ack = accept.accept_open_ack()?;
        open.open_recv_open_ack(&into_exts(open_ack))?;
        Ok(who)
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
        assert_eq!(
            r,
            Ok(Some(AuthIdentity(b"alice".to_vec()))),
            "matching user/password authenticates, AS alice"
        );
    }

    /// R2566 — the identity that comes out is the one that was VERIFIED, not
    /// merely the one the peer claimed.
    ///
    /// The discriminator is a responder whose table holds TWO users: a helper
    /// that returned "some username" would be satisfied by either name, so the
    /// handshake is run twice against the SAME table and each run must yield
    /// its OWN principal. That is what makes this an identity assertion rather
    /// than a presence one -- the previous signature could not have failed it,
    /// because it returned nothing to compare.
    #[test]
    fn the_authenticated_username_is_the_one_returned() {
        let table = alloc::vec![
            (b"alice".to_vec(), b"s3cret".to_vec()),
            (b"bob".to_vec(), b"hunter2".to_vec()),
        ];
        let as_alice = run_handshake(
            UsrPwdMethod::initiator(b"alice".to_vec(), b"s3cret".to_vec()),
            UsrPwdMethod::responder(table.clone(), 0x1234_5678),
        );
        let as_bob = run_handshake(
            UsrPwdMethod::initiator(b"bob".to_vec(), b"hunter2".to_vec()),
            UsrPwdMethod::responder(table, 0x1234_5678),
        );
        assert_eq!(as_alice, Ok(Some(AuthIdentity(b"alice".to_vec()))));
        assert_eq!(as_bob, Ok(Some(AuthIdentity(b"bob".to_vec()))));
        assert_ne!(as_alice, as_bob, "the two runs must not agree");
    }

    /// R2566 — a REJECTED handshake surfaces no identity at all, so nothing
    /// downstream can read a principal out of a failed authentication. The
    /// error arm carries no username by construction (`Result`'s `Err` has no
    /// room for one), and this pins that it stays that way.
    #[test]
    fn a_rejected_handshake_yields_no_identity() {
        let r = run_handshake(
            UsrPwdMethod::initiator(b"alice".to_vec(), b"wrong".to_vec()),
            UsrPwdMethod::responder(
                alloc::vec![(b"alice".to_vec(), b"s3cret".to_vec())],
                0x1234_5678,
            ),
        );
        assert!(r.is_err(), "a bad password must not authenticate");
        assert_eq!(r.ok().flatten(), None, "and must name nobody");
    }

    /// R2566 — an INITIATOR-role method (empty lookup) authenticates nobody on
    /// the accept side. It is the arm that keeps `Some` meaningful: without it,
    /// "returns an identity" and "is a responder" would be indistinguishable.
    #[test]
    fn an_initiator_role_method_authenticates_nobody() {
        let mut m = UsrPwdMethod::initiator(b"alice".to_vec(), b"s3cret".to_vec());
        assert_eq!(m.accept_recv_open_syn(None), Ok(None));
    }

    /// R2567 — the five cases UPSTREAM'S OWN TEST exercises, so the matrix is
    /// derived rather than invented (`usrpwd.rs` @ `authenticator_usrpwd_config`
    /// writes exactly these five files and asserts ok / err / err / err / err).
    #[test]
    fn the_dictionary_rules_are_upstreams() {
        assert_eq!(
            parse_dictionary("usr1:pwd1\n"),
            Ok(alloc::vec![(b"usr1".to_vec(), b"pwd1".to_vec())])
        );
        assert_eq!(
            parse_dictionary("usr1\n"),
            Err(DictionaryError::MissingSeparator)
        );
        assert_eq!(
            parse_dictionary("usr1:\n"),
            Err(DictionaryError::EmptyPassword)
        );
        assert_eq!(parse_dictionary(":pwd1\n"), Err(DictionaryError::EmptyUser));
        assert_eq!(parse_dictionary(":\n"), Err(DictionaryError::EmptyUser));
    }

    /// R2567 — three behaviours upstream's IMPLEMENTATION has that its tests do
    /// not cover. Recorded separately because "upstream tests this" and
    /// "upstream's code happens to do this" are different strengths of claim,
    /// and a later round comparing against a newer upstream should know which
    /// is which.
    ///
    /// The colon case is the one that matters in practice: splitting on the
    /// LAST separator, or refusing extras, would silently truncate any password
    /// containing `:` and lock out its user with a "bad password" that names the
    /// wrong cause.
    #[test]
    fn the_dictionary_rules_upstream_only_implements() {
        assert_eq!(
            parse_dictionary("\n\n  \nusr1:pwd1\n\n"),
            Ok(alloc::vec![(b"usr1".to_vec(), b"pwd1".to_vec())]),
            "blank lines are skipped"
        );
        assert_eq!(
            parse_dictionary("  usr1  :  pwd1  \n"),
            Ok(alloc::vec![(b"usr1".to_vec(), b"pwd1".to_vec())]),
            "lines and fields are trimmed"
        );
        assert_eq!(
            parse_dictionary("usr1:a:b:c\n"),
            Ok(alloc::vec![(b"usr1".to_vec(), b"a:b:c".to_vec())]),
            "the FIRST colon splits, so a password may contain colons"
        );
    }

    /// R2567 — a malformed line fails the WHOLE load rather than being skipped.
    /// A dictionary that silently dropped an entry would authenticate fewer
    /// users than its operator believes, with nothing anywhere saying so.
    #[test]
    fn one_bad_line_fails_the_whole_dictionary() {
        assert_eq!(
            parse_dictionary("good:pw\nbroken\nalso:fine\n"),
            Err(DictionaryError::MissingSeparator)
        );
    }

    /// R2567 — an EMPTY responder table means NOT CONFIGURED, not "configured
    /// with nobody".
    ///
    /// This is the arm that guards the conversion from the old empty-vec
    /// sentinel to `Option<Box<dyn CredentialSource>>`. Wrapping an empty table
    /// in a source would compile, type-check and pass every other test here,
    /// while inverting an authentication default: a node that does not respond
    /// to usrpwd would become one that rejects every peer. The previous shape
    /// could not express the bug; the new one can, so it is pinned. Upstream
    /// folds identically -- `from_config` returns `None`, never an empty table.
    #[test]
    fn an_empty_responder_table_is_not_a_responder() {
        let mut empty = UsrPwdMethod::responder(alloc::vec![], 0x1234_5678);
        assert_eq!(
            empty.accept_init_ack(),
            Ok(None),
            "an empty table must issue NO challenge -- it is not a responder"
        );
        assert_eq!(
            empty.accept_recv_open_syn(None),
            Ok(None),
            "and must admit rather than reject, exactly as before the conversion"
        );

        // The twin that keeps the assertion above from passing vacuously: a
        // NON-empty table is a responder and does issue a challenge.
        let mut configured = UsrPwdMethod::responder(
            alloc::vec![(b"alice".to_vec(), b"s3cret".to_vec())],
            0x1234_5678,
        );
        assert!(
            matches!(configured.accept_init_ack(), Ok(Some(_))),
            "a configured responder must issue its challenge"
        );
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
    fn a_responder_requires_the_initsyn_offer() {
        // A configured responder (non-empty lookup) rejects an InitSyn that
        // carries no usrpwd offer — it must not silently bypass auth.
        let mut resp =
            UsrPwdMethod::responder(alloc::vec![(b"alice".to_vec(), b"pw".to_vec())], 0x42);
        assert_eq!(
            resp.accept_recv_init_syn(None),
            Err(AuthError::Rejected("usrpwd: missing InitSyn offer"))
        );
        // An initiator-role method (empty lookup) does not require the offer.
        let mut init = UsrPwdMethod::initiator(b"bob".to_vec(), b"pw".to_vec());
        assert_eq!(init.accept_recv_init_syn(None), Ok(()));
    }

    #[test]
    fn set_challenge_nonce_refreshes_the_initack_challenge() {
        // The InitAck Z64 must reflect the LATEST injected nonce — the live
        // wiring refreshes it per accepted handshake (replay defense). Tested
        // at the method (not the value-blind handshake: an initiator HMACs
        // against whatever InitAck nonce it receives, so a full round-trip
        // authenticates for ANY nonce and cannot witness the refresh).
        let mut r = UsrPwdMethod::responder(
            alloc::vec![(b"alice".to_vec(), b"pw".to_vec())],
            0x1111_1111,
        );
        assert_eq!(
            r.accept_init_ack().unwrap(),
            Some(AuthSubExt::Z64(0x1111_1111))
        );
        r.set_challenge_nonce(0x2222_2222);
        assert_eq!(
            r.accept_init_ack().unwrap(),
            Some(AuthSubExt::Z64(0x2222_2222)),
            "InitAck must carry the refreshed nonce, not the construction one"
        );
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

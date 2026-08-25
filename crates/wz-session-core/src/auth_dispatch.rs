// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The method-agnostic Z_EXT_AUTH dispatch kernel (`session-extauth`) — the wz
//! mirror of zenoh `establishment/ext/auth/mod.rs` (`Auth` / `AuthFsm`'s
//! OpenFsm + AcceptFsm).
//!
//! # Shape
//!
//! zenoh carries N auth methods (pubkey id `0x1`, usrpwd id `0x2`) multiplexed
//! into ONE auth ext: each method contributes a `ZExtUnknown` sub-extension
//! keyed by its method id, the sub-exts are encoded as a chain into the auth
//! ext's ZBuf payload, and the peer demultiplexes by id (`ztake!`). wz mirrors
//! this exactly: an [`AuthMethod`] contributes / consumes a per-method
//! [`AuthSubExt`] at each of the four handshake stages, and [`AuthDispatch`]
//! mux/demuxes them through the [`crate::ext_chain`] inner chain wrapped by the
//! [`crate::extauth`] outer auth ext (id `0x3`). The multi-step state lives
//! INSIDE each method (`&mut self`), riding the existing four establishment
//! messages — no new session FSM state (the OQ-W10/W2 resolution).
//!
//! # Per-stage encoding
//!
//! A method's sub-ext encoding varies per stage (zenoh usrpwd: InitSyn `Unit`,
//! InitAck `Z64` nonce, OpenSyn `ZBuf` {user,hmac}, OpenAck `Unit`), so a method
//! returns / receives an [`AuthSubExt`] that names BOTH the encoding and the
//! value; the kernel maps it to / from the matching wire `ExtEntry` body
//! (`ExtUnit` / `ExtZint` / `ExtZbuf`). A method never touches the wire types.
//!
//! # Scope
//!
//! This kernel is method-agnostic + transport-agnostic: it does NOT itself
//! authenticate (that is the concrete methods — usrpwd / pubkey) and does NOT
//! wire into the live Init/Open handshake (the `handshake_encode` /
//! `session_glue` integration is a follow-on atom). It is unit-tested here
//! against a test-double method exercising the full four-stage open<->accept
//! exchange + method-id routing + all three sub-ext encodings.

use alloc::boxed::Box;
use alloc::vec::Vec;

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_unit::ExtUnit;
use wz_codecs::ext_zbuf::ExtZbufOwned;
use wz_codecs::ext_zint::ExtZint;

use crate::codec_owned::owned_bytes;
use crate::ext_chain::{decode_ext_chain, encode_ext_chain};
use crate::ext_header::{EXT_ENC_Z64, EXT_ENC_ZBUF};
use crate::extauth::{decode_auth_ext, encode_auth_ext};

/// The Z_EXT_AUTH method-id namespace (the wz mirror of zenoh `auth::id`). Each
/// concrete method routes its per-method sub-ext within the auth ext by this id;
/// the kernel demuxes by it (`ztake!` analogue). Centralised here in the
/// method-agnostic kernel so the id space is one auditable SSOT as the catalog
/// grows — a method must NOT hard-code a bare literal. Ids must fit the 4-bit
/// ext id field (`<= 0x0F`) and be distinct across a dispatch (both enforced in
/// [`AuthDispatch::new`]).
pub mod id {
    /// pubkey RSA challenge-response (zenoh `id::PUBKEY`).
    pub const PUBKEY: u8 = 0x1;
    /// usrpwd HMAC challenge-response (zenoh `id::USRPWD`).
    pub const USRPWD: u8 = 0x2;
}

/// A method's per-stage auth sub-extension — the encoding + value zenoh's
/// `ZExt{Unit,Z64,ZBuf}` carries inside the auth ext, abstracted so a method
/// never touches the wire `ExtEntry` types. A `Unit` is a present-but-empty
/// marker (e.g. usrpwd InitSyn "I offer usrpwd" / OpenAck "OK"), `Z64` a small
/// integer (usrpwd InitAck nonce), `Zbuf` an opaque byte blob (usrpwd OpenSyn
/// {user, hmac}).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthSubExt {
    /// A present, empty marker (`ZExtUnit`).
    Unit,
    /// A small unsigned integer (`ZExtZ64`).
    Z64(u64),
    /// An opaque byte payload (`ZExtZBuf`).
    Zbuf(Vec<u8>),
}

impl AuthSubExt {
    /// Build the wire `ExtEntry` for this sub-ext under method `id` (the kernel's
    /// mux step). The header carries `id` plus the encoding marker.
    ///
    /// `pub(crate)` so the UN-wrapped [`extmultilink`](crate::extmultilink)
    /// 0x4 dispatch reuses the SAME sub-ext -> `ExtEntryOwned` mapping (zenoh's
    /// `.transmute()`, id 0x1 -> 0x4): passing `MULTILINK_EXT_ID` produces the
    /// 0x4 ext DIRECTLY (Unit -> header `0x04`, Zbuf -> `0x44`), with NO inner
    /// method-id frame — the anti-mux path. One mapping SSOT, two callers.
    pub(crate) fn into_ext_entry(self, id: u8) -> Result<ExtEntryOwned, AuthError> {
        Ok(match self {
            AuthSubExt::Unit => ExtEntryOwned {
                header: id,
                body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
            },
            AuthSubExt::Z64(value) => ExtEntryOwned {
                header: id | EXT_ENC_Z64,
                body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value }),
            },
            AuthSubExt::Zbuf(bytes) => ExtEntryOwned {
                header: id | EXT_ENC_ZBUF,
                body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                    value_len: bytes.len() as u64,
                    value: owned_bytes(&bytes)
                        .map_err(|_| AuthError::Rejected("payload too large"))?,
                }),
            },
        })
    }

    /// Project a demuxed wire `ExtEntry` body back into an `AuthSubExt` (the
    /// kernel's demux step). `None` for an encoding this kernel does not carry.
    ///
    /// `pub(crate)` so the UN-wrapped [`extmultilink`](crate::extmultilink)
    /// 0x4 dispatch reuses the SAME body -> sub-ext projection when demuxing the
    /// peer's 0x4 ext (parallel to this kernel's `find_method_sub_ext`).
    pub(crate) fn from_body(body: &ExtEntryOwnedVariant) -> Option<AuthSubExt> {
        match body {
            ExtEntryOwnedVariant::CodecZenohExtUnit(_) => Some(AuthSubExt::Unit),
            ExtEntryOwnedVariant::CodecZenohExtZint(z) => Some(AuthSubExt::Z64(z.value)),
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => {
                Some(AuthSubExt::Zbuf(z.value.as_slice().to_vec()))
            }
            _ => None,
        }
    }
}

/// An auth dispatch error. The handshake aborts on either: a malformed auth ext
/// (the inner method chain did not decode) or a method rejecting the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// The auth ext payload (the inner per-method chain) failed to decode.
    Decode,
    /// A method rejected the handshake — a bad credential, a missing required
    /// sub-ext, or a payload that exceeds the bounded owned mirror.
    Rejected(&'static str),
}

/// One auth method — the wz mirror of a zenoh per-method FSM (`AuthUsrPwdFsm` /
/// `AuthPubKeyFsm`). It owns its multi-step state (`&mut self`) and contributes
/// / consumes an [`AuthSubExt`] at each of the four establishment stages, keyed
/// by [`id`](Self::id). A stage a method does not participate in keeps the
/// default (contribute nothing / admit) — usrpwd, e.g., offers a `Unit` on
/// InitSyn, a `Z64` nonce on InitAck, a `Zbuf` HMAC on OpenSyn.
///
/// `Send` supertrait: an [`AuthDispatch`] lives in the session's
/// [`SessionLinkActions`](crate::session_actions::SessionLinkActions) auth slot,
/// behind the per-runtime `Mutex` whose `with_mutex_mut` requires `T: Send` for
/// every runtime (the AP tokio profile shares it across tasks). The shipped
/// methods (usrpwd; pubkey's `rsa` key material is `Send` too) are naturally
/// `Send` (owned `Vec<u8>` credentials); the bound makes that an explicit,
/// compiler-checked contract rather than an accidental property. It is a
/// requirement on EVERY future method — one wrapping a non-`Send` handle (e.g.
/// an `Rc`-based HSM client) would fail to compile here, by design.
pub trait AuthMethod: Send {
    /// The method id used to route this method's sub-ext within the auth ext
    /// (zenoh `id::PUBKEY = 0x1` / `id::USRPWD = 0x2`). Must be `<= 0x0F` (the
    /// 4-bit ext id field).
    fn id(&self) -> u8;

    // ── Open (initiator) side ────────────────────────────────────────────
    /// Produce this method's InitSyn sub-ext (or `None` to contribute nothing).
    fn open_init_syn(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        Ok(None)
    }
    /// Consume the peer's InitAck sub-ext for this method (`None` if absent).
    fn open_recv_init_ack(&mut self, _sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        Ok(())
    }
    /// Produce this method's OpenSyn sub-ext (or `None`).
    fn open_open_syn(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        Ok(None)
    }
    /// Consume the peer's OpenAck sub-ext for this method (`None` if absent).
    fn open_recv_open_ack(&mut self, _sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        Ok(())
    }

    // ── Accept (responder) side ──────────────────────────────────────────
    /// Consume the peer's InitSyn sub-ext for this method (`None` if absent).
    fn accept_recv_init_syn(&mut self, _sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        Ok(())
    }
    /// Produce this method's InitAck sub-ext (or `None`).
    fn accept_init_ack(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        Ok(None)
    }
    /// Consume the peer's OpenSyn sub-ext for this method (`None` if absent).
    fn accept_recv_open_syn(&mut self, _sub: Option<AuthSubExt>) -> Result<(), AuthError> {
        Ok(())
    }
    /// Produce this method's OpenAck sub-ext (or `None`).
    fn accept_open_ack(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
        Ok(None)
    }

    /// Refresh this method's per-handshake challenge nonce (responder side).
    /// The no_std core draws no entropy (`getrandom` has no bare-metal
    /// backend), so the AP layer supplies a FRESH cryptographically-random
    /// `nonce` per accepted handshake — the wz mirror of zenoh drawing
    /// `prng.gen()` in `StateAccept::new` (usrpwd.rs:169-174). Default no-op
    /// (a method without a challenge — e.g. an initiator-only or
    /// nonce-free method — ignores it). See the [`UsrPwdMethod::responder`]
    /// security contract: a fixed / reused nonce is a replay hole.
    fn set_challenge_nonce(&mut self, _nonce: u64) {}

    /// R311y205 (transport-multilink IMPL-2b-ii) — the peer's captured ephemeral
    /// public key, in its canonical encoded ZPublicKey byte form, or `None` if
    /// this method captures no peer key (e.g. usrpwd) or has not yet reached the
    /// stage that captures it. The 0x4 multilink dispatch surfaces this
    /// ([`crate::extmultilink::MultiLinkDispatch::captured_peer_pubkey`]) so the
    /// aggregation join can bind a second link to the same logical session by
    /// byte-equality of the ephemeral key (the wz analogue of zenoh's
    /// `init_existing_transport_unicast` pubkey config-equality). Byte-stable: the
    /// SAME peer key always encodes identically, so equality of the encoded bytes
    /// IS equality of the key. Default `None` (a non-pubkey method). Reached only
    /// under `transport-multilink`; the default keeps the trait total for the
    /// usrpwd / auth methods that never override it.
    fn captured_peer_key_bytes(&self) -> Option<Vec<u8>> {
        None
    }
}

/// The composable auth dispatch — holds the negotiated methods and mux/demuxes
/// their per-stage sub-exts into / out of the Z_EXT_AUTH ext. An EMPTY dispatch
/// produces no auth ext (auth disabled) and admits every stage, mirroring zenoh
/// `Auth::default()`.
pub struct AuthDispatch {
    methods: Vec<Box<dyn AuthMethod>>,
}

impl AuthDispatch {
    /// A dispatch over `methods` (each must carry a distinct [`AuthMethod::id`]).
    /// The distinctness + 4-bit-id-bound invariants the kernel relies on for
    /// routing are debug-asserted here so a construction mistake is a checked
    /// failure in test/debug rather than a silent wrong-routing at runtime
    /// (the dispatch's `find_method_sub_ext` picks the FIRST id match).
    pub fn new(methods: Vec<Box<dyn AuthMethod>>) -> Self {
        debug_assert!(
            methods.iter().all(|m| m.id() <= 0x0F),
            "auth method id must fit the 4-bit ext id field (<= 0x0F)"
        );
        debug_assert!(
            {
                let mut ids: Vec<u8> = methods.iter().map(|m| m.id()).collect();
                ids.sort_unstable();
                ids.windows(2).all(|w| w[0] != w[1])
            },
            "auth methods must carry distinct ids (sub-exts route by id)"
        );
        Self { methods }
    }

    /// Whether no method is configured — the fast path (no auth ext emitted).
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }

    /// Refresh every method's per-handshake challenge nonce (responder side).
    /// The AP layer draws a FRESH cryptographically-random `nonce` per accepted
    /// handshake (OS entropy — the no_std core cannot) and fans it out here, so
    /// the responder's InitAck challenge is never reused across handshakes (the
    /// [`UsrPwdMethod::responder`] replay-defense contract). A method without a
    /// challenge ignores it (the trait default no-op).
    pub fn set_challenge_nonce(&mut self, nonce: u64) {
        for m in self.methods.iter_mut() {
            m.set_challenge_nonce(nonce);
        }
    }

    /// Multiplex per-method `(id, sub-ext)` contributions into the outer auth
    /// ext: each becomes an `id`-keyed sub-ext (encoding per the [`AuthSubExt`])
    /// in an inner chain, encoded and wrapped by the R1 codec. No contributions
    /// -> no auth ext.
    fn mux(contributions: Vec<(u8, AuthSubExt)>) -> Result<Option<ExtEntryOwned>, AuthError> {
        if contributions.is_empty() {
            return Ok(None);
        }
        let mut inner = Vec::with_capacity(contributions.len());
        for (id, sub) in contributions {
            inner.push(sub.into_ext_entry(id)?);
        }
        let inner_bytes = encode_ext_chain(&inner);
        let outer =
            encode_auth_ext(&inner_bytes).map_err(|_| AuthError::Rejected("auth ext too large"))?;
        Ok(Some(outer))
    }

    /// Demultiplex the peer's establishment ext chain back into the inner
    /// per-method sub-exts (empty when the peer carried no auth ext).
    fn demux(peer_exts: &[ExtEntryOwned]) -> Result<Vec<ExtEntryOwned>, AuthError> {
        match decode_auth_ext(peer_exts) {
            None => Ok(Vec::new()),
            Some(inner_bytes) => {
                let mut cursor = SceCursor::new(inner_bytes);
                decode_ext_chain(&mut cursor).map_err(|_| AuthError::Decode)
            }
        }
    }

    /// The single send-stage driver: run `f` over every method, collect the
    /// non-`None` sub-exts keyed by id, mux into the outer auth ext.
    fn send_stage(
        &mut self,
        f: impl Fn(&mut dyn AuthMethod) -> Result<Option<AuthSubExt>, AuthError>,
    ) -> Result<Option<ExtEntryOwned>, AuthError> {
        let mut contributions = Vec::new();
        for m in self.methods.iter_mut() {
            let id = m.id();
            if let Some(sub) = f(m.as_mut())? {
                contributions.push((id, sub));
            }
        }
        Self::mux(contributions)
    }

    /// The single recv-stage driver: demux the peer's auth ext, then run `f` over
    /// every method with ITS sub-ext (`None` if the peer sent none for that id).
    fn recv_stage(
        &mut self,
        peer_exts: &[ExtEntryOwned],
        f: impl Fn(&mut dyn AuthMethod, Option<AuthSubExt>) -> Result<(), AuthError>,
    ) -> Result<(), AuthError> {
        let inner = Self::demux(peer_exts)?;
        for m in self.methods.iter_mut() {
            let sub = find_method_sub_ext(&inner, m.id());
            f(m.as_mut(), sub)?;
        }
        Ok(())
    }

    /// Open side: produce the InitSyn auth ext (to append to the InitSyn exts).
    pub fn open_init_syn(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.open_init_syn())
    }
    /// Open side: consume the peer InitAck's auth ext.
    pub fn open_recv_init_ack(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage(peer_exts, |m, s| m.open_recv_init_ack(s))
    }
    /// Open side: produce the OpenSyn auth ext.
    pub fn open_open_syn(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.open_open_syn())
    }
    /// Open side: consume the peer OpenAck's auth ext.
    pub fn open_recv_open_ack(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage(peer_exts, |m, s| m.open_recv_open_ack(s))
    }

    /// Accept side: consume the peer InitSyn's auth ext.
    pub fn accept_recv_init_syn(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage(peer_exts, |m, s| m.accept_recv_init_syn(s))
    }
    /// Accept side: produce the InitAck auth ext.
    pub fn accept_init_ack(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.accept_init_ack())
    }
    /// Accept side: consume the peer OpenSyn's auth ext.
    pub fn accept_recv_open_syn(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage(peer_exts, |m, s| m.accept_recv_open_syn(s))
    }
    /// Accept side: produce the OpenAck auth ext.
    pub fn accept_open_ack(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.accept_open_ack())
    }
}

impl Default for AuthDispatch {
    /// An empty dispatch — no method configured, so it emits no auth ext and
    /// admits every stage (the wz mirror of zenoh `Auth::default()`). This is
    /// the [`SessionLinkActions`](crate::session_actions::SessionLinkActions)
    /// auth-slot default until the AP layer installs a configured dispatch.
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// Find the sub-ext whose id matches `id` in a demuxed inner chain (the
/// `ztake!` analogue), projected to an [`AuthSubExt`]. `None` when the peer sent
/// no sub-ext for that id (or one in an encoding this kernel does not carry).
fn find_method_sub_ext(entries: &[ExtEntryOwned], id: u8) -> Option<AuthSubExt> {
    entries
        .iter()
        .find(|e| e.ext_id() == id)
        .and_then(|e| AuthSubExt::from_body(&e.body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    /// A test-double method exercising the four-stage mux/demux + id routing +
    /// ALL THREE sub-ext encodings: the open side offers `Unit` on InitSyn; the
    /// accept side issues a `Z64` nonce on InitAck; the open side echoes it as a
    /// `Zbuf` on OpenSyn; the accept side verifies and confirms with `Unit` on
    /// OpenAck; the open side checks the confirmation. The two terminal flags are
    /// shared `Rc<Cell>` the test inspects after the methods are boxed.
    struct EchoMethod {
        id: u8,
        nonce: u64,
        open_recv_nonce: Option<u64>,
        accept_offered: Arc<AtomicBool>,
        accept_verified: Arc<AtomicBool>,
        open_confirmed: Arc<AtomicBool>,
    }

    impl EchoMethod {
        fn new(
            id: u8,
            nonce: u64,
            accept_offered: Arc<AtomicBool>,
            accept_verified: Arc<AtomicBool>,
            open_confirmed: Arc<AtomicBool>,
        ) -> Self {
            Self {
                id,
                nonce,
                open_recv_nonce: None,
                accept_offered,
                accept_verified,
                open_confirmed,
            }
        }
        fn boxed(id: u8, nonce: u64) -> Box<dyn AuthMethod> {
            Box::new(Self::new(
                id,
                nonce,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            ))
        }
    }

    impl AuthMethod for EchoMethod {
        fn id(&self) -> u8 {
            self.id
        }
        // Open side: offer Unit on InitSyn, store the Z64 nonce from InitAck,
        // echo it as a Zbuf on OpenSyn, check the Unit OK on OpenAck.
        fn open_init_syn(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
            Ok(Some(AuthSubExt::Unit))
        }
        fn open_recv_init_ack(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
            match sub {
                Some(AuthSubExt::Z64(n)) => {
                    self.open_recv_nonce = Some(n);
                    Ok(())
                }
                _ => Err(AuthError::Rejected("expected Z64 nonce")),
            }
        }
        fn open_open_syn(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
            Ok(self
                .open_recv_nonce
                .map(|n| AuthSubExt::Zbuf(n.to_le_bytes().to_vec())))
        }
        fn open_recv_open_ack(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
            self.open_confirmed
                .store(sub == Some(AuthSubExt::Unit), Ordering::SeqCst);
            Ok(())
        }
        // Accept side: note the Unit offer, issue the Z64 nonce, verify the Zbuf
        // echo, confirm with Unit.
        fn accept_recv_init_syn(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
            self.accept_offered
                .store(sub == Some(AuthSubExt::Unit), Ordering::SeqCst);
            Ok(())
        }
        fn accept_init_ack(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
            Ok(Some(AuthSubExt::Z64(self.nonce)))
        }
        fn accept_recv_open_syn(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
            let ok = sub == Some(AuthSubExt::Zbuf(self.nonce.to_le_bytes().to_vec()));
            self.accept_verified.store(ok, Ordering::SeqCst);
            if !ok {
                return Err(AuthError::Rejected("nonce mismatch"));
            }
            Ok(())
        }
        fn accept_open_ack(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
            Ok(Some(AuthSubExt::Unit))
        }
    }

    fn exts(ext: Option<ExtEntryOwned>) -> Vec<ExtEntryOwned> {
        ext.into_iter().collect()
    }

    #[test]
    fn four_stage_open_accept_round_trip_authenticates_all_encodings() {
        let accept_offered = Arc::new(AtomicBool::new(false));
        let accept_verified = Arc::new(AtomicBool::new(false));
        let open_confirmed = Arc::new(AtomicBool::new(false));
        let mut accept = AuthDispatch::new(alloc::vec![Box::new(EchoMethod::new(
            0x2,
            0x4243_4445,
            accept_offered.clone(),
            accept_verified.clone(),
            Arc::new(AtomicBool::new(false)),
        )) as _]);
        let mut open = AuthDispatch::new(alloc::vec![Box::new(EchoMethod::new(
            0x2,
            0x4243_4445,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            open_confirmed.clone(),
        )) as _]);

        // InitSyn (Unit): the open side offers usrpwd; the accept side notes it.
        let init_syn = open.open_init_syn().unwrap();
        assert!(init_syn.is_some(), "InitSyn carries the Unit offer");
        accept.accept_recv_init_syn(&exts(init_syn)).unwrap();
        assert!(
            accept_offered.load(Ordering::SeqCst),
            "accept saw the Unit offer"
        );

        // InitAck (Z64): the accept side issues the nonce; the open side stores it.
        let init_ack = accept.accept_init_ack().unwrap();
        open.open_recv_init_ack(&exts(init_ack)).unwrap();

        // OpenSyn (Zbuf): the open side echoes the nonce; the accept side verifies.
        let open_syn = open.open_open_syn().unwrap();
        accept.accept_recv_open_syn(&exts(open_syn)).unwrap();

        // OpenAck (Unit): the accept side confirms; the open side checks.
        let open_ack = accept.accept_open_ack().unwrap();
        open.open_recv_open_ack(&exts(open_ack)).unwrap();

        assert!(
            accept_verified.load(Ordering::SeqCst),
            "accept verified the echoed nonce"
        );
        assert!(
            open_confirmed.load(Ordering::SeqCst),
            "open confirmed the Unit OK"
        );
    }

    #[test]
    fn a_tampered_open_syn_is_rejected_by_the_accept_side() {
        let mut accept = AuthDispatch::new(alloc::vec![EchoMethod::boxed(0x2, 0x42)]);
        // Forge an OpenSyn auth ext carrying the WRONG nonce for method 0x2.
        let forged =
            AuthDispatch::mux(alloc::vec![(0x2, AuthSubExt::Zbuf(alloc::vec![0x00]))]).unwrap();
        let err = accept.accept_recv_open_syn(&exts(forged)).unwrap_err();
        assert_eq!(err, AuthError::Rejected("nonce mismatch"));
    }

    #[test]
    fn two_methods_route_by_id_independently() {
        // Two methods (ids 0x1 and 0x2) each issue a distinct nonce on InitAck;
        // the open side must route each sub-ext to the matching method by id,
        // then echo the right nonce so the accept side verifies BOTH.
        let mut accept = AuthDispatch::new(alloc::vec![
            EchoMethod::boxed(0x1, 0xAAAA),
            EchoMethod::boxed(0x2, 0xBBBB)
        ]);
        let mut open = AuthDispatch::new(alloc::vec![
            EchoMethod::boxed(0x1, 0xAAAA),
            EchoMethod::boxed(0x2, 0xBBBB)
        ]);
        let init_ack = accept.accept_init_ack().unwrap();
        open.open_recv_init_ack(&exts(init_ack)).unwrap();
        let open_syn = open.open_open_syn().unwrap();
        // Both nonces verify -> no Err (a cross-routed nonce would mismatch).
        accept.accept_recv_open_syn(&exts(open_syn)).unwrap();
    }

    #[test]
    fn an_empty_dispatch_emits_no_auth_ext_and_admits() {
        let mut d = AuthDispatch::new(alloc::vec![]);
        assert!(d.is_empty());
        assert!(
            d.open_init_syn().unwrap().is_none(),
            "no methods -> no auth ext"
        );
        // A recv with no peer auth ext admits (no method to reject).
        d.open_recv_init_ack(&[]).unwrap();
    }
}

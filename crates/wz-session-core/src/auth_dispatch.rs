// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! this exactly: an [`AuthMethod`] contributes / consumes a per-method payload
//! at each of the four handshake stages, and [`AuthDispatch`] mux/demuxes them
//! through the [`crate::ext_chain`] inner chain wrapped by the
//! [`crate::extauth`] outer auth ext (id `0x3`). The multi-step state lives
//! INSIDE each method (`&mut self`), riding the existing four establishment
//! messages — no new session FSM state (the OQ-W10/W2 resolution).
//!
//! # Scope
//!
//! This kernel is method-agnostic + transport-agnostic: it does NOT itself
//! authenticate (that is the concrete methods — usrpwd / pubkey, follow-on
//! atoms) and does NOT wire into the live Init/Open handshake (the
//! `handshake_encode` / `session_glue` integration is a follow-on atom). It is
//! unit-tested here against a test-double method exercising the full four-stage
//! open<->accept exchange + method-id routing.

use alloc::boxed::Box;
use alloc::vec::Vec;

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;

use crate::codec_owned::owned_bytes;
use crate::ext_chain::{decode_ext_chain, encode_ext_chain};
use crate::extauth::{decode_auth_ext, encode_auth_ext};

/// ENC_ZBUF marker for an inner per-method sub-ext header (the 2-bit encoding
/// field `0b10` at bits 5..6). Mirrors `ext_nodeid::EXT_ENC_ZBUF`, redefined
/// here because `ext_nodeid` is codec-plane-gated (`codec-push` / `-declare` /
/// `-request`) and so absent on a session-extauth-only build.
const ENC_ZBUF: u8 = 0x40;

/// Extract the 4-bit ext id from a header (mirrors `ext_nodeid::ext_id`; see
/// [`ENC_ZBUF`] for why it is not imported).
fn ext_id(header: u8) -> u8 {
    header & 0x0F
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
/// / consumes a per-method payload at each of the four establishment stages,
/// keyed by [`id`](Self::id). A stage a method does not participate in keeps the
/// default (contribute nothing / admit) — usrpwd, e.g., sends nothing on
/// InitSyn, a nonce on InitAck, an HMAC on OpenSyn.
pub trait AuthMethod {
    /// The method id used to route this method's sub-ext within the auth ext
    /// (zenoh `id::PUBKEY = 0x1` / `id::USRPWD = 0x2`). Must be `<= 0x0F` (the
    /// 4-bit ext id field).
    fn id(&self) -> u8;

    // ── Open (initiator) side ────────────────────────────────────────────
    /// Produce this method's InitSyn payload (or `None` to contribute nothing).
    fn open_init_syn(&mut self) -> Result<Option<Vec<u8>>, AuthError> {
        Ok(None)
    }
    /// Consume the peer's InitAck payload for this method (`None` if absent).
    fn open_recv_init_ack(&mut self, _payload: Option<&[u8]>) -> Result<(), AuthError> {
        Ok(())
    }
    /// Produce this method's OpenSyn payload (or `None`).
    fn open_open_syn(&mut self) -> Result<Option<Vec<u8>>, AuthError> {
        Ok(None)
    }
    /// Consume the peer's OpenAck payload for this method (`None` if absent).
    fn open_recv_open_ack(&mut self, _payload: Option<&[u8]>) -> Result<(), AuthError> {
        Ok(())
    }

    // ── Accept (responder) side ──────────────────────────────────────────
    /// Consume the peer's InitSyn payload for this method (`None` if absent).
    fn accept_recv_init_syn(&mut self, _payload: Option<&[u8]>) -> Result<(), AuthError> {
        Ok(())
    }
    /// Produce this method's InitAck payload (or `None`).
    fn accept_init_ack(&mut self) -> Result<Option<Vec<u8>>, AuthError> {
        Ok(None)
    }
    /// Consume the peer's OpenSyn payload for this method (`None` if absent).
    fn accept_recv_open_syn(&mut self, _payload: Option<&[u8]>) -> Result<(), AuthError> {
        Ok(())
    }
    /// Produce this method's OpenAck payload (or `None`).
    fn accept_open_ack(&mut self) -> Result<Option<Vec<u8>>, AuthError> {
        Ok(None)
    }
}

/// The composable auth dispatch — holds the negotiated methods and mux/demuxes
/// their per-stage payloads into / out of the Z_EXT_AUTH ext. An EMPTY dispatch
/// produces no auth ext (auth disabled) and admits every stage, mirroring zenoh
/// `Auth::default()`.
pub struct AuthDispatch {
    methods: Vec<Box<dyn AuthMethod>>,
}

impl AuthDispatch {
    /// A dispatch over `methods` (each must carry a distinct [`AuthMethod::id`]).
    pub fn new(methods: Vec<Box<dyn AuthMethod>>) -> Self {
        Self { methods }
    }

    /// Whether no method is configured — the fast path (no auth ext emitted).
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }

    /// Multiplex per-method `(id, payload)` contributions into the outer auth
    /// ext: each becomes an `id | ENC_ZBUF` sub-ext in an inner chain, encoded
    /// and wrapped by the R1 codec. No contributions -> no auth ext.
    fn mux(contributions: &[(u8, Vec<u8>)]) -> Result<Option<ExtEntryOwned>, AuthError> {
        if contributions.is_empty() {
            return Ok(None);
        }
        let mut inner = Vec::with_capacity(contributions.len());
        for (id, payload) in contributions {
            inner.push(ExtEntryOwned {
                header: id | ENC_ZBUF,
                body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                    value_len: payload.len() as u64,
                    value: owned_bytes(payload)
                        .map_err(|_| AuthError::Rejected("payload too large"))?,
                }),
            });
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
    /// non-`None` contributions keyed by id, mux into the outer auth ext.
    fn send_stage(
        &mut self,
        f: impl Fn(&mut dyn AuthMethod) -> Result<Option<Vec<u8>>, AuthError>,
    ) -> Result<Option<ExtEntryOwned>, AuthError> {
        let mut contributions = Vec::new();
        for m in self.methods.iter_mut() {
            let id = m.id();
            if let Some(payload) = f(m.as_mut())? {
                contributions.push((id, payload));
            }
        }
        Self::mux(&contributions)
    }

    /// The single recv-stage driver: demux the peer's auth ext, then run `f`
    /// over every method with ITS sub-ext payload (`None` if the peer sent none
    /// for that method id).
    fn recv_stage(
        &mut self,
        peer_exts: &[ExtEntryOwned],
        f: impl Fn(&mut dyn AuthMethod, Option<&[u8]>) -> Result<(), AuthError>,
    ) -> Result<(), AuthError> {
        let inner = Self::demux(peer_exts)?;
        for m in self.methods.iter_mut() {
            let payload = find_method_payload(&inner, m.id());
            f(m.as_mut(), payload)?;
        }
        Ok(())
    }

    /// Open side: produce the InitSyn auth ext (to append to the InitSyn exts).
    pub fn open_init_syn(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.open_init_syn())
    }
    /// Open side: consume the peer InitAck's auth ext.
    pub fn open_recv_init_ack(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage(peer_exts, |m, p| m.open_recv_init_ack(p))
    }
    /// Open side: produce the OpenSyn auth ext.
    pub fn open_open_syn(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.open_open_syn())
    }
    /// Open side: consume the peer OpenAck's auth ext.
    pub fn open_recv_open_ack(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage(peer_exts, |m, p| m.open_recv_open_ack(p))
    }

    /// Accept side: consume the peer InitSyn's auth ext.
    pub fn accept_recv_init_syn(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage(peer_exts, |m, p| m.accept_recv_init_syn(p))
    }
    /// Accept side: produce the InitAck auth ext.
    pub fn accept_init_ack(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.accept_init_ack())
    }
    /// Accept side: consume the peer OpenSyn's auth ext.
    pub fn accept_recv_open_syn(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage(peer_exts, |m, p| m.accept_recv_open_syn(p))
    }
    /// Accept side: produce the OpenAck auth ext.
    pub fn accept_open_ack(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.accept_open_ack())
    }
}

/// Find the payload of the sub-ext whose id matches `id` in a demuxed inner
/// chain (the `ztake!` analogue). `None` when the peer sent no sub-ext for it.
fn find_method_payload(entries: &[ExtEntryOwned], id: u8) -> Option<&[u8]> {
    for e in entries {
        if ext_id(e.header) == id {
            if let ExtEntryOwnedVariant::CodecZenohExtZbuf(z) = &e.body {
                return Some(z.value.as_slice());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use core::cell::Cell;

    /// A test-double method: a challenge-response that proves the four-stage
    /// mux/demux + id routing. The accept side issues a nonce on InitAck; the
    /// open side echoes it on OpenSyn; the accept side verifies the echo and
    /// confirms (0x01) on OpenAck; the open side checks the confirmation. The
    /// two terminal flags are shared `Rc<Cell>` the test inspects after the
    /// methods are boxed into the dispatch.
    struct EchoMethod {
        id: u8,
        nonce: u8,
        open_recv_nonce: Option<u8>,
        accept_verified: Rc<Cell<bool>>,
        open_confirmed: Rc<Cell<bool>>,
    }

    impl EchoMethod {
        fn new(
            id: u8,
            nonce: u8,
            accept_verified: Rc<Cell<bool>>,
            open_confirmed: Rc<Cell<bool>>,
        ) -> Self {
            Self {
                id,
                nonce,
                open_recv_nonce: None,
                accept_verified,
                open_confirmed,
            }
        }
        fn boxed(id: u8, nonce: u8) -> Box<dyn AuthMethod> {
            Box::new(Self::new(
                id,
                nonce,
                Rc::new(Cell::new(false)),
                Rc::new(Cell::new(false)),
            ))
        }
    }

    impl AuthMethod for EchoMethod {
        fn id(&self) -> u8 {
            self.id
        }
        // Open side: silent on InitSyn, store the nonce from InitAck, echo it on
        // OpenSyn, check the OK byte on OpenAck.
        fn open_recv_init_ack(&mut self, payload: Option<&[u8]>) -> Result<(), AuthError> {
            let nonce = *payload
                .and_then(|p| p.first())
                .ok_or(AuthError::Rejected("no nonce"))?;
            self.open_recv_nonce = Some(nonce);
            Ok(())
        }
        fn open_open_syn(&mut self) -> Result<Option<Vec<u8>>, AuthError> {
            Ok(self.open_recv_nonce.map(|n| alloc::vec![n]))
        }
        fn open_recv_open_ack(&mut self, payload: Option<&[u8]>) -> Result<(), AuthError> {
            self.open_confirmed.set(payload == Some(&[0x01]));
            Ok(())
        }
        // Accept side: issue the nonce on InitAck, verify the echo on OpenSyn,
        // confirm with 0x01 on OpenAck.
        fn accept_init_ack(&mut self) -> Result<Option<Vec<u8>>, AuthError> {
            Ok(Some(alloc::vec![self.nonce]))
        }
        fn accept_recv_open_syn(&mut self, payload: Option<&[u8]>) -> Result<(), AuthError> {
            let ok = payload == Some(&[self.nonce]);
            self.accept_verified.set(ok);
            if !ok {
                return Err(AuthError::Rejected("nonce mismatch"));
            }
            Ok(())
        }
        fn accept_open_ack(&mut self) -> Result<Option<Vec<u8>>, AuthError> {
            Ok(Some(alloc::vec![0x01]))
        }
    }

    fn exts(ext: Option<ExtEntryOwned>) -> Vec<ExtEntryOwned> {
        ext.into_iter().collect()
    }

    #[test]
    fn four_stage_open_accept_round_trip_authenticates() {
        let accept_verified = Rc::new(Cell::new(false));
        let open_confirmed = Rc::new(Cell::new(false));
        let mut accept = AuthDispatch::new(alloc::vec![Box::new(EchoMethod::new(
            0x2,
            0x42,
            accept_verified.clone(),
            Rc::new(Cell::new(false)),
        )) as _]);
        let mut open = AuthDispatch::new(alloc::vec![Box::new(EchoMethod::new(
            0x2,
            0x42,
            Rc::new(Cell::new(false)),
            open_confirmed.clone(),
        )) as _]);

        // InitSyn: the echo method is silent, so no auth ext rides the InitSyn.
        let init_syn = open.open_init_syn().unwrap();
        assert!(init_syn.is_none(), "echo method is silent on InitSyn");
        accept.accept_recv_init_syn(&exts(init_syn)).unwrap();

        // InitAck: the accept side issues the nonce; the open side stores it.
        let init_ack = accept.accept_init_ack().unwrap();
        assert!(init_ack.is_some(), "InitAck carries the nonce auth ext");
        open.open_recv_init_ack(&exts(init_ack)).unwrap();

        // OpenSyn: the open side echoes the nonce; the accept side verifies.
        let open_syn = open.open_open_syn().unwrap();
        assert!(open_syn.is_some(), "OpenSyn carries the echoed nonce");
        accept.accept_recv_open_syn(&exts(open_syn)).unwrap();

        // OpenAck: the accept side confirms; the open side checks.
        let open_ack = accept.accept_open_ack().unwrap();
        open.open_recv_open_ack(&exts(open_ack)).unwrap();

        assert!(
            accept_verified.get(),
            "accept side verified the echoed nonce"
        );
        assert!(open_confirmed.get(), "open side confirmed the OK byte");
    }

    #[test]
    fn a_tampered_open_syn_is_rejected_by_the_accept_side() {
        let mut accept = AuthDispatch::new(alloc::vec![EchoMethod::boxed(0x2, 0x42)]);
        // Forge an OpenSyn auth ext carrying the WRONG nonce for method 0x2.
        let forged = AuthDispatch::mux(&[(0x2, alloc::vec![0x00])]).unwrap();
        let err = accept.accept_recv_open_syn(&exts(forged)).unwrap_err();
        assert_eq!(err, AuthError::Rejected("nonce mismatch"));
    }

    #[test]
    fn two_methods_route_by_id_independently() {
        // Two methods (ids 0x1 and 0x2) each issue a distinct nonce on InitAck;
        // the open side must route each sub-ext to the matching method by id,
        // then echo the right nonce so the accept side verifies BOTH.
        let mut accept = AuthDispatch::new(alloc::vec![
            EchoMethod::boxed(0x1, 0xAA),
            EchoMethod::boxed(0x2, 0xBB)
        ]);
        let mut open = AuthDispatch::new(alloc::vec![
            EchoMethod::boxed(0x1, 0xAA),
            EchoMethod::boxed(0x2, 0xBB)
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

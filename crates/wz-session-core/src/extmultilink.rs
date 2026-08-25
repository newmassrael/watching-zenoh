// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the Z_EXT_MULTILINK establishment extension wire shape
//! (`transport-multilink`) — the wz mirror of zenoh
//! `unicast/establishment/ext/multilink.rs`.
//!
//! # The UN-wrapped 0x4 envelope (vs the 0x3 auth mux)
//!
//! zenoh's multilink carries a mutual RSA challenge-response — the SAME crypto
//! as the pubkey auth method — but on its OWN establishment ext id `0x4`
//! (`Z_EXT_MULTILINK`), NOT inside the `0x3` auth ext. Crucially zenoh does this
//! by `.transmute()`-ing the pubkey FSM's ext payload: the value is UNCHANGED,
//! only the ext id flips `0x1 -> 0x4`. There is NO inner method-id frame and NO
//! inner ext-chain length — the 0x4 ext body is the bare pubkey / challenge
//! bytes directly.
//!
//! This is the decisive divergence from [`crate::auth_dispatch`]. The auth
//! dispatch WRAPS each method's sub-ext: `AuthDispatch::mux` builds an
//! `id`-keyed inner `ExtEntry` (`into_ext_entry(0x1)`), `encode_ext_chain`s it,
//! and wraps the result in the outer `0x3` auth ext (`encode_auth_ext`). So a
//! pubkey handshake over the auth path emits `0x3 -> [0x41 hdr][len][pubkey…]`.
//! Multilink must NOT do that: it maps the method's `AuthSubExt` DIRECTLY to a
//! `0x4` `ExtEntry` (`into_ext_entry(0x4)` — the wz analogue of zenoh's
//! `.transmute()`), so the body is `[pubkey…]` with no inner header.
//!
//! # Reuse (one mapping SSOT, two carriers)
//!
//! Rather than re-derive the `AuthSubExt <-> ExtEntry` mapping, this module
//! reuses [`AuthSubExt::into_ext_entry`](crate::auth_dispatch::AuthSubExt) (send)
//! and [`AuthSubExt::from_body`](crate::auth_dispatch::AuthSubExt) (recv) with
//! [`MULTILINK_EXT_ID`] as the id — the auth kernel and the multilink envelope
//! share ONE mapping, differing only in the ext id and the un-wrapped framing.
//! `AuthSubExt::Unit -> ExtEntry` header `0x04`; `AuthSubExt::Zbuf -> ExtEntry`
//! header `0x44` (`EXT_ENC_ZBUF | 0x04`); `AuthSubExt::Z64 -> ExtEntry` header
//! `0x24` (`EXT_ENC_Z64 | 0x04`).
//!
//! # rsa-free
//!
//! Like [`AuthDispatch`](crate::auth_dispatch::AuthDispatch) holds
//! `Vec<Box<dyn AuthMethod>>`, [`MultiLinkDispatch`] holds ONE
//! `Box<dyn AuthMethod>` — the concrete ephemeral-RSA `PubKeyMethod` is injected
//! by the AP runtime (`wz-runtime-tokio`), so this no_std session-kernel module
//! stays free of the std-only `rsa` dependency. This module is the establishment
//! codec + dispatch ONLY; the aggregation core (`MultiLinkSink` + the add-link
//! decision at `Step::Opened`) is a follow-on atom.

use alloc::boxed::Box;

use wz_codecs::ext_entry::ExtEntryOwned;

use crate::auth_dispatch::{AuthError, AuthMethod, AuthSubExt};

/// Z_EXT_MULTILINK ext id on the Init / Open establishment messages — zenoh
/// `init.rs` / `open.rs` `zextzbuf!(0x4, false)` (`Z_EXT_MULTILINK`). Distinct
/// from the `0x3` auth ext ([`AUTH_EXT_ID`](crate::extauth::AUTH_EXT_ID)):
/// establishment messages have their own ext id space (0x1 QoS, 0x2 Shm, 0x3
/// Auth, 0x4 MultiLink, 0x5 LowLatency, 0x6 Compression, 0x7 Patch).
pub const MULTILINK_EXT_ID: u8 = crate::ext_header::establishment_ext_id::MULTILINK;

/// zenoh's `close::reason::INVALID` (0x02) — the wire close-reason code for a
/// link rejected because its captured ephemeral multilink pubkey did NOT match
/// the logical session's bound identity (config-equality failure). Distinct from
/// the wz [`CloseReason`](crate::close_reason::CloseReason) enum (whose
/// `Invalid` discriminant is `1`, a wz-internal value); the aggregation reject
/// emits the zenoh wire code so a wz↔zenohd link-close is byte-faithful.
pub const CLOSE_REASON_INVALID: u8 = 0x02;

/// zenoh's `close::reason::MAX_LINKS` (0x04) — the wire close-reason code for a
/// link rejected because the session already holds `max_links` links (the
/// aggregation over-limit reject).
pub const CLOSE_REASON_MAX_LINKS: u8 = 0x04;

/// The single-method multilink dispatch — the wz mirror of zenoh's
/// `MultiLinkFsm` (which drives ONE `AuthPubKeyFsm`). It holds ONE
/// [`AuthMethod`] (the concrete ephemeral-pubkey method, injected rsa-free from
/// the AP runtime) and drives it across the four establishment stages, mapping
/// each produced [`AuthSubExt`] DIRECTLY to a 0x4 [`ExtEntryOwned`] (the
/// UN-wrapped envelope — NO [`auth_dispatch`](crate::auth_dispatch) mux) and
/// projecting the peer's 0x4 ext back into the sub-ext its recv hook consumes.
pub struct MultiLinkDispatch {
    method: Box<dyn AuthMethod>,
    /// R311y205 (slice-1 MF-A) — set when the peer sent NO 0x4 ext at the FIRST
    /// recv stage (accept-side InitSyn, open-side InitAck): multilink is
    /// gracefully DISABLED for this session, the wz mirror of zenoh's
    /// `state.pubkey = None; return Ok` (`establishment/ext/multilink.rs`
    /// :148-150 / :187-189 / :298-300). Once disabled the remaining send stages
    /// contribute NO 0x4 ext and any further inbound 0x4 is ignored, so a peer
    /// that does not negotiate multilink (stock zenohd, a `max_links=1` wz node)
    /// completes single-link instead of being torn down for a "missing pubkey"
    /// reject.
    disabled: bool,
}

impl MultiLinkDispatch {
    /// A dispatch driving `method` (the injected ephemeral-pubkey method). The
    /// method owns its multi-step handshake state (`&mut self`), exactly as an
    /// [`AuthDispatch`](crate::auth_dispatch::AuthDispatch)'s methods do.
    pub fn new(method: Box<dyn AuthMethod>) -> Self {
        Self {
            method,
            disabled: false,
        }
    }

    /// Refresh the method's per-handshake challenge nonce (responder side) — the
    /// wz mirror of [`AuthDispatch::set_challenge_nonce`](crate::auth_dispatch::AuthDispatch::set_challenge_nonce),
    /// for the single held method. The AP accept seam draws a fresh
    /// cryptographically-random nonce per accepted handshake; a method without a
    /// challenge (an initiator-only method) ignores it (the trait default no-op).
    pub fn set_challenge_nonce(&mut self, nonce: u64) {
        self.method.set_challenge_nonce(nonce);
    }

    /// The single send-stage driver: run `f` over the held method; if it
    /// contributes a sub-ext, map it DIRECTLY to a 0x4 [`ExtEntryOwned`] (the
    /// UN-wrapped `.transmute()` — [`AuthSubExt::into_ext_entry`] with
    /// [`MULTILINK_EXT_ID`], NO mux). `None` contribution -> no 0x4 ext.
    fn send_stage(
        &mut self,
        f: impl FnOnce(&mut dyn AuthMethod) -> Result<Option<AuthSubExt>, AuthError>,
    ) -> Result<Option<ExtEntryOwned>, AuthError> {
        // MF-A: a gracefully-disabled dispatch emits NO further 0x4 ext (the
        // session already fell back to single-link at the first recv stage).
        if self.disabled {
            return Ok(None);
        }
        match f(self.method.as_mut())? {
            Some(sub) => Ok(Some(sub.into_ext_entry(MULTILINK_EXT_ID)?)),
            None => Ok(None),
        }
    }

    /// The single recv-stage driver: project the peer's 0x4 ext out of the
    /// establishment ext chain (`None` if absent), then feed it to the method's
    /// recv hook `f`.
    fn recv_stage(
        &mut self,
        peer_exts: &[ExtEntryOwned],
        f: impl FnOnce(&mut dyn AuthMethod, Option<AuthSubExt>) -> Result<(), AuthError>,
    ) -> Result<(), AuthError> {
        // MF-A: a gracefully-disabled dispatch ignores any inbound 0x4 ext.
        if self.disabled {
            return Ok(());
        }
        let sub = decode_multilink_ext(peer_exts);
        f(self.method.as_mut(), sub)
    }

    /// R311y205 (slice-1 MF-A) — the FIRST recv stage (accept-side InitSyn,
    /// open-side InitAck), where the peer either negotiates multilink (a 0x4 ext
    /// is present) or does not. When ABSENT, gracefully DISABLE the dispatch (the
    /// wz mirror of zenoh's `state.pubkey = None; return Ok`) instead of feeding
    /// `None` to the method — the pubkey responder / initiator rejects a missing
    /// offer, which the drive loop turns into a session teardown
    /// ([`crate::drive`] `DriverLoopOutcome::AuthRejected`), so a stock-zenohd /
    /// `max_links=1` peer that sends no 0x4 would be hard-rejected rather than
    /// falling back to single-link. When PRESENT, drive the method normally.
    fn recv_stage_first(
        &mut self,
        peer_exts: &[ExtEntryOwned],
        f: impl FnOnce(&mut dyn AuthMethod, Option<AuthSubExt>) -> Result<(), AuthError>,
    ) -> Result<(), AuthError> {
        if self.disabled {
            return Ok(());
        }
        match decode_multilink_ext(peer_exts) {
            None => {
                self.disabled = true;
                Ok(())
            }
            Some(sub) => f(self.method.as_mut(), Some(sub)),
        }
    }

    // ── Open (initiator) side ────────────────────────────────────────────
    /// Open side: produce the InitSyn 0x4 ext (append to the InitSyn exts).
    pub fn open_init_syn(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.open_init_syn())
    }
    /// Open side: consume the peer InitAck's 0x4 ext. This is the open side's
    /// FIRST recv stage — an ABSENT 0x4 gracefully disables multilink (MF-A).
    pub fn open_recv_init_ack(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage_first(peer_exts, |m, s| m.open_recv_init_ack(s))
    }
    /// Open side: produce the OpenSyn 0x4 ext.
    pub fn open_open_syn(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.open_open_syn())
    }
    /// Open side: consume the peer OpenAck's 0x4 ext.
    pub fn open_recv_open_ack(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage(peer_exts, |m, s| m.open_recv_open_ack(s))
    }

    // ── Accept (responder) side ──────────────────────────────────────────
    /// Accept side: consume the peer InitSyn's 0x4 ext (captures the initiator's
    /// ephemeral pubkey). This is the accept side's FIRST recv stage — an ABSENT
    /// 0x4 gracefully disables multilink (single-link fallback, MF-A).
    pub fn accept_recv_init_syn(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage_first(peer_exts, |m, s| m.accept_recv_init_syn(s))
    }
    /// Accept side: produce the InitAck 0x4 ext (the challenge).
    pub fn accept_init_ack(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.accept_init_ack())
    }
    /// Accept side: consume the peer OpenSyn's 0x4 ext (verifies the challenge).
    pub fn accept_recv_open_syn(&mut self, peer_exts: &[ExtEntryOwned]) -> Result<(), AuthError> {
        self.recv_stage(peer_exts, |m, s| m.accept_recv_open_syn(s))
    }
    /// Accept side: produce the OpenAck 0x4 ext (the Unit confirmation).
    pub fn accept_open_ack(&mut self) -> Result<Option<ExtEntryOwned>, AuthError> {
        self.send_stage(|m| m.accept_open_ack())
    }

    /// R311y205 (transport-multilink IMPL-2b-ii) — the peer's captured ephemeral
    /// multilink public key, in its canonical encoded ZPublicKey byte form, once
    /// the handshake stage that captures it has run (the responder captures the
    /// initiator's key on InitSyn, the initiator the responder's key on InitAck);
    /// `None` before then. Delegates to the injected method's
    /// [`AuthMethod::captured_peer_key_bytes`]. The aggregation join binds a
    /// logical session to this key and admits a second link only when its captured
    /// key is byte-equal (the wz analogue of zenoh's
    /// `init_existing_transport_unicast` pubkey config-equality).
    pub fn captured_peer_pubkey(&self) -> Option<alloc::vec::Vec<u8>> {
        self.method.captured_peer_key_bytes()
    }
}

/// Project the 0x4 multilink sub-ext out of a decoded establishment ext chain —
/// the parallel of [`decode_auth_ext`](crate::extauth::decode_auth_ext), but for
/// the UN-wrapped 0x4 ext: the body maps straight to an [`AuthSubExt`] (via the
/// shared [`AuthSubExt::from_body`] projection), NO inner method chain to demux.
/// `None` when the peer carried no 0x4 ext (it did not negotiate multilink).
pub fn decode_multilink_ext(extensions: &[ExtEntryOwned]) -> Option<AuthSubExt> {
    extensions
        .iter()
        .find(|e| e.ext_id() == MULTILINK_EXT_ID)
        .and_then(|e| AuthSubExt::from_body(&e.body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext_chain::{decode_ext_chain, encode_ext_chain};
    use alloc::vec;
    use alloc::vec::Vec;
    use sce_forge_runtime::codec::SceCursor;
    use wz_codecs::ext_entry::ExtEntryOwnedVariant;

    /// A codec-only mock method exercising the 0x4 envelope framing (header
    /// bytes + un-wrapped body + demux) in isolation from any RSA crypto (the
    /// full challenge-response round-trip lives in wz-runtime-tokio, where `rsa`
    /// is available). It emits a fixed `Zbuf` on InitSyn / a `Unit` on OpenAck,
    /// and on `accept_recv_init_syn` ASSERTS the sub-ext it is handed equals
    /// `expected` (returning `Err` on mismatch) — so a passing recv proves the
    /// dispatch demuxed the peer's 0x4 ext into exactly the right sub-ext.
    struct MockMethod {
        init_syn_body: Vec<u8>,
        expected_recv: Option<AuthSubExt>,
    }

    impl AuthMethod for MockMethod {
        fn id(&self) -> u8 {
            // The dispatch keys the 0x4 ext off MULTILINK_EXT_ID, never the
            // method id; any value fits the 4-bit field.
            0x1
        }
        fn open_init_syn(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
            Ok(Some(AuthSubExt::Zbuf(self.init_syn_body.clone())))
        }
        fn accept_recv_init_syn(&mut self, sub: Option<AuthSubExt>) -> Result<(), AuthError> {
            if sub == self.expected_recv {
                Ok(())
            } else {
                Err(AuthError::Rejected("recv sub-ext mismatch"))
            }
        }
        fn accept_open_ack(&mut self) -> Result<Option<AuthSubExt>, AuthError> {
            Ok(Some(AuthSubExt::Unit))
        }
    }

    fn open_with(body: Vec<u8>) -> MultiLinkDispatch {
        MultiLinkDispatch::new(Box::new(MockMethod {
            init_syn_body: body,
            expected_recv: None,
        }))
    }

    fn accept_expecting(expected: Option<AuthSubExt>) -> MultiLinkDispatch {
        MultiLinkDispatch::new(Box::new(MockMethod {
            init_syn_body: Vec::new(),
            expected_recv: expected,
        }))
    }

    /// The InitSyn 0x4 ext carries the method's `Zbuf` payload UN-WRAPPED: header
    /// byte `0x44` (`EXT_ENC_ZBUF | 0x04`) and the body value byte-identical to
    /// the raw bytes the method returned — NO inner method-id header (the
    /// anti-mux assertion). Then the ext round-trips through the chain codec back
    /// to the same `AuthSubExt`.
    #[test]
    fn init_syn_0x4_ext_is_unwrapped_and_round_trips() {
        let body = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mut open = open_with(body.clone());

        let ext = open
            .open_init_syn()
            .unwrap()
            .expect("InitSyn emits a 0x4 ext");
        assert_eq!(
            ext.header, 0x44,
            "EXT_ENC_ZBUF (0x40) | MULTILINK_EXT_ID (0x04)"
        );
        // Anti-mux: the 0x4 ZBuf body is the method's raw bytes, NOT an inner
        // ext chain (which would start with a 0x41 method-id header byte).
        match &ext.body {
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => {
                assert_eq!(z.value.as_slice(), body.as_slice(), "un-wrapped raw body");
            }
            other => panic!("expected a ZBuf 0x4 body, got {other:?}"),
        }

        // Encode into an ext chain and decode it back — the projector recovers
        // the same sub-ext (peer-side demux parity).
        let bytes = encode_ext_chain(&[ext]);
        let mut cursor = SceCursor::new(&bytes);
        let peer = decode_ext_chain(&mut cursor).unwrap();
        assert_eq!(decode_multilink_ext(&peer), Some(AuthSubExt::Zbuf(body)));
    }

    /// The OpenAck 0x4 ext carries a `Unit`: header byte `0x04` (id, no encoding
    /// marker) and an empty body.
    #[test]
    fn open_ack_0x4_ext_is_a_bare_unit() {
        let mut accept = accept_expecting(None);
        let ext = accept
            .accept_open_ack()
            .unwrap()
            .expect("OpenAck emits a 0x4 ext");
        assert_eq!(
            ext.header, 0x04,
            "MULTILINK_EXT_ID (0x04), no encoding marker"
        );
        assert!(
            matches!(ext.body, ExtEntryOwnedVariant::CodecZenohExtUnit(_)),
            "a Unit sub-ext maps to a 0x4 Unit ext body"
        );
    }

    /// The recv stage projects the peer's 0x4 ext into the sub-ext the method
    /// consumes: a chain carrying the peer's InitSyn 0x4 Zbuf hands the method
    /// exactly that Zbuf (recv returns `Ok`), while a chain with NO 0x4 ext hands
    /// the method `None`.
    #[test]
    fn recv_stage_demuxes_the_0x4_ext_to_the_method() {
        let body = vec![0x01, 0x02, 0x03];
        // The peer's InitSyn 0x4 ext, produced by the open side.
        let peer_ext = open_with(body.clone())
            .open_init_syn()
            .unwrap()
            .expect("0x4 ext");

        // The method expects exactly the peer's Zbuf; a successful recv proves
        // the dispatch demuxed the 0x4 ext into the right sub-ext.
        let mut accept = accept_expecting(Some(AuthSubExt::Zbuf(body)));
        accept
            .accept_recv_init_syn(&[peer_ext])
            .expect("recv hands the method the un-wrapped 0x4 Zbuf");

        // A chain WITHOUT a 0x4 ext at the FIRST recv stage gracefully DISABLES
        // multilink (MF-A): the dispatch returns Ok WITHOUT feeding the method,
        // and every later send stage then contributes no 0x4 ext.
        let mut accept_none = accept_expecting(None);
        accept_none
            .accept_recv_init_syn(&[])
            .expect("absent 0x4 ext -> graceful single-link disable");
        assert!(
            accept_none.accept_init_ack().unwrap().is_none(),
            "a disabled dispatch stages NO 0x4 InitAck (single-link fallback)"
        );
    }
}

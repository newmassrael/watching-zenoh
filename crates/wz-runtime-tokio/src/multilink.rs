// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y205 (transport-multilink IMPL-1) — the AP-side ephemeral-RSA glue for
//! the §5.1 multi-link aggregation feature: the process-wide ephemeral keypair
//! plus the open / accept [`MultiLinkDispatch`] constructors.
//!
//! # Why the crypto lives here
//!
//! The 0x4 multilink handshake is the SAME mutual RSA challenge-response as the
//! pubkey auth method, and `rsa` requires std — so, exactly like
//! [`extauth_pubkey`](crate::extauth_pubkey), the concrete
//! [`PubKeyMethod`](crate::extauth_pubkey::PubKeyMethod) lives in this AP crate,
//! not the no_std session kernel. The kernel holds only the rsa-free
//! [`MultiLinkDispatch`] (the 0x4 envelope + the single-method driver); this
//! module INJECTS the concrete method into it, the wz analogue of zenoh's
//! `MultiLink::make` building an `AuthPubKey` and handing it to `MultiLinkFsm`.
//!
//! # Ephemeral, process-wide
//!
//! zenoh mints a fresh `KEY_SIZE = 512` RSA key inside each `MultiLink::make`
//! (`unicast/establishment/ext/multilink.rs`); wz mints ONE per process (the
//! node's aggregation identity, not a per-session secret) via a [`OnceLock`], so
//! every link this node opens / accepts presents a stable ephemeral pubkey — the
//! key by which a second link is bound to the same logical session (the
//! config-equality gate is IMPL-2). The responder disables key lookup
//! (`None` = accept any initiator key), mirroring zenoh's
//! `MultiLink::make` `auth.disable_lookup()`.
//!
//! # Scope
//!
//! IMPL-1 provides the keypair + the two dispatch constructors ONLY; they are
//! NOT yet wired into the live Init / Open establishment path (that transplant,
//! plus the `MultiLinkSink` aggregation core and the add-link decision, is
//! IMPL-2). The 0x4 wire round-trip is unit-tested here (where `rsa` is
//! available).

use std::sync::Arc;
use std::sync::OnceLock;

use rsa::RsaPrivateKey;

use wz_session_core::extmultilink::MultiLinkDispatch;

use crate::extauth_pubkey::{generate_keypair, PubKeyMethod};
use crate::session_glue::SessionLinkActions;

/// The process-wide ephemeral RSA-512 multilink identity, minted once.
static MULTILINK_KEYPAIR: OnceLock<RsaPrivateKey> = OnceLock::new();

/// The RSA key size zenoh's multilink uses (`KEY_SIZE` in
/// `unicast/establishment/ext/multilink.rs`). Ephemeral + AP-only; the wire is
/// key-size-agnostic, so this stays byte-compatible with a zenohd peer that
/// mints its own 512-bit multilink key.
const MULTILINK_KEY_SIZE: usize = 512;

/// The process-wide ephemeral RSA-512 multilink keypair, minting it from OS
/// entropy on first access. Stable for the process lifetime: it is the node's
/// multi-link aggregation identity (the pubkey a peer's second link is matched
/// against), not a per-session secret.
///
/// # Panics
///
/// If RSA key generation fails (OS entropy unavailable) — an unrecoverable
/// environment fault at node bring-up, the wz analogue of zenoh's `?` in
/// `MultiLink::make`. It is drawn once, before any link is dialed.
pub fn multilink_keypair() -> &'static RsaPrivateKey {
    MULTILINK_KEYPAIR.get_or_init(|| {
        generate_keypair(MULTILINK_KEY_SIZE)
            .expect("ephemeral multilink RSA-512 keypair generation")
    })
}

/// Build the OPEN-side (initiator) [`MultiLinkDispatch`] over this node's
/// ephemeral keypair — it offers the node's pubkey on InitSyn and proves
/// possession by decrypting + relaying the responder's challenge. The wz mirror
/// of zenoh's `MultiLink::open` driving `pubkey::StateOpen`.
pub fn open_multilink_dispatch() -> MultiLinkDispatch {
    MultiLinkDispatch::new(Box::new(PubKeyMethod::initiator(
        multilink_keypair().clone(),
    )))
}

/// Build the ACCEPT-side (responder) [`MultiLinkDispatch`] over this node's
/// ephemeral keypair, with key lookup DISABLED (`None` = accept any initiator
/// key — zenoh's `MultiLink::make` `auth.disable_lookup()`). It challenges the
/// initiator and captures its ephemeral pubkey (the key IMPL-2 binds a second
/// link to the logical session by).
pub fn accept_multilink_dispatch() -> MultiLinkDispatch {
    MultiLinkDispatch::new(Box::new(PubKeyMethod::responder(
        multilink_keypair().clone(),
        None,
    )))
}

/// R311y205 (transport-multilink IMPL-2b-iii) — the outcome of aggregating a
/// SECOND (or later) established link into a `primary` link's logical session
/// (the multilink JOIN decision).
pub enum JoinOutcome {
    /// The link aggregated: drive its steady state with this "joined" actions
    /// handle — the transplant, re-homing the secondary link's `LinkState` onto
    /// the primary's SHARED `SessionCore` (so its RX admits against the shared
    /// per-channel rx-SN gate and its sends route across the shared link set),
    /// while keeping the secondary's own per-link lease / F2 state. No new
    /// forwarder face is registered; the link shares the primary's face.
    Joined(Arc<SessionLinkActions>),
    /// Rejected — the second link's captured ephemeral pubkey did NOT byte-match
    /// the session's bound identity (config-equality failure). An INVALID
    /// (0x02) link-only close was emitted on the secondary's own link.
    InvalidPubkey,
    /// Rejected — the session already holds `max_links` links. A MAX_LINKS
    /// (0x04) link-only close was emitted on the secondary's own link.
    OverLimit,
}

/// Emit the aggregation-reject link-only close on `secondary`'s own link, when
/// the close codec is present. A no-op stub otherwise (signature-stable).
fn reject_link(secondary: &Arc<SessionLinkActions>, reason: u8) {
    #[cfg(feature = "codec-close")]
    secondary.send_link_close(reason);
    #[cfg(not(feature = "codec-close"))]
    let _ = (secondary, reason);
}

/// R311y205 (transport-multilink IMPL-2b-iii) — the multilink JOIN: aggregate the
/// established `secondary` link into `primary`'s logical session. This is the wz
/// analogue of zenoh's `init_existing_transport_unicast` add-link path, and the
/// reusable core both a wz↔wz e2e and the accept-loop `Step::Opened` add-link
/// decision drive.
///
/// Steps (MF-D order — GATE before any mutation): (1) config-equality on the
/// captured ephemeral pubkey FIRST, minting the [`PubkeyBound`] witness (INVALID
/// reject on mismatch/absence) so a mismatched link is unrepresentable as an
/// `add_link` argument AND a rejected link leaves the primary's single-link send
/// path completely untouched (no `register_first_link` side effect); (2) register
/// the primary's OWN link into the shared set (idempotent — link 1 was driving
/// single-link until now); (3) enforce `max_links` room (MAX_LINKS reject when
/// full); (4) on success attach the secondary's `LinkState` to the shared core
/// and return the transplant handle. The caller drives the returned handle in
/// place of the secondary's own actions (whose throwaway `SessionCore` is then
/// discarded).
///
/// [`PubkeyBound`]: wz_session_core::session_actions::PubkeyBound
pub fn join_link(
    primary: &Arc<SessionLinkActions>,
    secondary: &Arc<SessionLinkActions>,
    max_links: usize,
) -> JoinOutcome {
    use wz_session_core::extmultilink::{CLOSE_REASON_INVALID, CLOSE_REASON_MAX_LINKS};

    // (1) config-equality gate FIRST (MF-D) — mint the PubkeyBound witness on the
    // captured ephemeral multilink pubkey BEFORE mutating the primary's link set,
    // so a REJECTED link (mismatched or uncaptured pubkey) leaves the primary's
    // single-link send path untouched (`register_first_link` is not reached).
    let candidate = match secondary.multilink_pubkey() {
        Some(k) => k,
        None => {
            reject_link(secondary, CLOSE_REASON_INVALID);
            return JoinOutcome::InvalidPubkey;
        }
    };
    let bound = match primary.authorize_link(&candidate) {
        Some(b) => b,
        None => {
            reject_link(secondary, CLOSE_REASON_INVALID);
            return JoinOutcome::InvalidPubkey;
        }
    };

    // (2) the primary's own link joins the aggregation set (idempotent) — only
    // now that the gate has passed.
    primary.register_first_link(primary.link.clone());

    // (3) max_links room — the primary's registered link counts toward the limit.
    if primary.link_count() >= max_links {
        reject_link(secondary, CLOSE_REASON_MAX_LINKS);
        return JoinOutcome::OverLimit;
    }

    // (4) attach the secondary's LinkState to the shared core + return the
    // transplant handle bound to that core.
    primary.add_link(secondary.link.clone(), bound);
    JoinOutcome::Joined(Arc::new(SessionLinkActions {
        core: primary.core.clone(),
        link: secondary.link.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPublicKey;
    use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
    use wz_session_core::vle::write_zbuf;

    /// Reconstruct zenoh's `ZPublicKey` encoding (two ZBufs, `n` then `e`, each
    /// little-endian) from a public key — the SAME bytes `extauth_pubkey`'s
    /// private `encode_pubkey` emits. The anti-mux assertion compares the 0x4
    /// InitSyn body against this, so it must match `encode_pubkey` exactly.
    fn expected_pubkey_zbufs(key: &RsaPublicKey) -> Vec<u8> {
        let mut out = Vec::new();
        write_zbuf(&mut out, &key.n().to_bytes_le());
        write_zbuf(&mut out, &key.e().to_bytes_le());
        out
    }

    /// Wrap a single emitted ext into the `&[ExtEntryOwned]` a recv stage reads.
    fn as_exts(ext: Option<ExtEntryOwned>) -> Vec<ExtEntryOwned> {
        ext.into_iter().collect()
    }

    /// The PRIMARY IMPL-1 gate: drive an initiator and a responder
    /// `MultiLinkDispatch` through the full four-message 0x4 handshake and assert
    /// (a) it completes, (b) mutual pubkey capture, (c) the 0x4 header bytes, and
    /// (d) the anti-mux un-wrapped body.
    #[test]
    fn multilink_0x4_handshake_round_trip() {
        // Distinct initiator / responder keypairs (a real 2-node deployment). The
        // responder's lookup PINS the initiator's exact pubkey (`Some([init_pub])`)
        // so a completed handshake PROVES the responder captured the correct
        // initiator key (b, responder side); the challenge verifying on OpenSyn
        // proves the initiator re-encrypted under the correct responder key it
        // captured on InitAck (b, initiator side).
        let init_priv = generate_keypair(512).unwrap();
        let init_pub = RsaPublicKey::from(&init_priv);
        let resp_priv = generate_keypair(512).unwrap();

        let mut open = MultiLinkDispatch::new(Box::new(PubKeyMethod::initiator(init_priv)));
        let mut accept = MultiLinkDispatch::new(Box::new(PubKeyMethod::responder(
            resp_priv,
            Some(vec![init_pub.clone()]),
        )));
        accept.set_challenge_nonce(0x1122_3344_5566_7788);

        // InitSyn (initiator -> responder): 0x4 ZBuf { my_pubkey }.
        let init_syn = open.open_init_syn().unwrap().expect("InitSyn 0x4 ext");
        assert_eq!(init_syn.header, 0x44, "InitSyn: EXT_ENC_ZBUF | 0x04");
        // (d) anti-mux: the 0x4 body is the bare ZPublicKey bytes (no inner 0x41
        // method-id header) — byte-identical to what encode_pubkey produces.
        match &init_syn.body {
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => assert_eq!(
                z.value.as_slice(),
                expected_pubkey_zbufs(&init_pub).as_slice(),
                "InitSyn 0x4 body is the un-wrapped ZPublicKey (n-ZBuf first), NOT a muxed inner chain"
            ),
            other => panic!("InitSyn 0x4 body must be a ZBuf, got {other:?}"),
        }
        accept
            .accept_recv_init_syn(&as_exts(Some(init_syn)))
            .unwrap();

        // InitAck (responder -> initiator): 0x4 ZBuf { my_pubkey, challenge_ct }.
        let init_ack = accept.accept_init_ack().unwrap().expect("InitAck 0x4 ext");
        assert_eq!(init_ack.header, 0x44, "InitAck: EXT_ENC_ZBUF | 0x04");
        open.open_recv_init_ack(&as_exts(Some(init_ack))).unwrap();

        // OpenSyn (initiator -> responder): 0x4 ZBuf { challenge_reenc }.
        let open_syn = open.open_open_syn().unwrap().expect("OpenSyn 0x4 ext");
        assert_eq!(open_syn.header, 0x44, "OpenSyn: EXT_ENC_ZBUF | 0x04");
        // (a)/(b): the responder decrypts the re-encrypted challenge and checks it
        // equals the nonce it issued — succeeds ONLY if both captures were correct.
        accept
            .accept_recv_open_syn(&as_exts(Some(open_syn)))
            .expect("responder verifies the challenge round-trip");

        // OpenAck (responder -> initiator): 0x4 Unit (bare confirmation).
        let open_ack = accept.accept_open_ack().unwrap().expect("OpenAck 0x4 ext");
        assert_eq!(
            open_ack.header, 0x04,
            "OpenAck: bare Unit 0x04, no encoding marker"
        );
        assert!(
            matches!(open_ack.body, ExtEntryOwnedVariant::CodecZenohExtUnit(_)),
            "OpenAck 0x4 body is a Unit"
        );
        // (a): the initiator requires the OpenAck Unit confirmation to complete.
        open.open_recv_open_ack(&as_exts(Some(open_ack)))
            .expect("initiator accepts the OpenAck confirmation");
    }

    /// The ephemeral-keypair glue constructors drive a complete handshake: a
    /// self-dial (open + accept both over the process-wide key, responder lookup
    /// disabled) exercises `multilink_keypair` / `open_multilink_dispatch` /
    /// `accept_multilink_dispatch` end-to-end.
    #[test]
    fn glue_constructors_complete_a_handshake() {
        // The process-wide key is stable across calls (OnceLock).
        assert_eq!(
            multilink_keypair(),
            multilink_keypair(),
            "the ephemeral keypair is minted once, process-wide"
        );

        let mut open = open_multilink_dispatch();
        let mut accept = accept_multilink_dispatch();
        accept.set_challenge_nonce(0xDEAD_BEEF_0000_0001);

        let init_syn = open.open_init_syn().unwrap();
        accept.accept_recv_init_syn(&as_exts(init_syn)).unwrap();
        let init_ack = accept.accept_init_ack().unwrap();
        open.open_recv_init_ack(&as_exts(init_ack)).unwrap();
        let open_syn = open.open_open_syn().unwrap();
        accept.accept_recv_open_syn(&as_exts(open_syn)).unwrap();
        let open_ack = accept.accept_open_ack().unwrap();
        open.open_recv_open_ack(&as_exts(open_ack)).unwrap();
    }

    /// R311y205 (slice-1 MF-A) — a wz ACCEPTOR with a multilink dispatch
    /// installed, fed an InitSyn that carries NO 0x4 ext (a stock zenohd peer or
    /// a `max_links=1` wz node), gracefully falls back to SINGLE-link: the accept
    /// side's first recv returns Ok (NOT a "missing pubkey" reject → no teardown),
    /// the acceptor's InitAck stages NO 0x4 ext, and no ephemeral pubkey is
    /// captured. The wz mirror of zenoh's `state.pubkey = None; return Ok`.
    #[test]
    fn acceptor_absent_0x4_disables_multilink_single_link() {
        let mut accept = accept_multilink_dispatch();
        accept.set_challenge_nonce(0x0102_0304_0506_0708);

        // The peer's InitSyn carries no 0x4 ext.
        accept
            .accept_recv_init_syn(&[])
            .expect("absent 0x4 -> graceful single-link fallback, NOT a teardown reject");

        // The acceptor emits NO 0x4 ext on its InitAck (multilink disabled).
        assert!(
            accept.accept_init_ack().unwrap().is_none(),
            "a disabled multilink dispatch stages no 0x4 Z_EXT_MULTILINK on its InitAck"
        );
        // Nothing was captured to bind a second link against.
        assert!(
            accept.captured_peer_pubkey().is_none(),
            "single-link fallback captures no ephemeral pubkey"
        );
    }

    /// The open-side symmetry of MF-A: the initiator always OFFERS its 0x4 on
    /// InitSyn, but if the peer's InitAck carries none (a non-multilink peer), it
    /// gracefully disables multilink — its subsequent OpenSyn stages no 0x4.
    #[test]
    fn initiator_absent_initack_0x4_disables_multilink() {
        let mut open = open_multilink_dispatch();
        assert!(
            open.open_init_syn().unwrap().is_some(),
            "the initiator always offers its ephemeral pubkey on InitSyn"
        );
        open.open_recv_init_ack(&[])
            .expect("absent InitAck 0x4 -> graceful disable, NOT a reject");
        assert!(
            open.open_open_syn().unwrap().is_none(),
            "a disabled dispatch stages no 0x4 OpenSyn (single-link fallback)"
        );
    }

    /// R311y205 (slice-1 MF-D test-gap) — `join_link`'s REJECT path: a 2nd link
    /// whose captured ephemeral pubkey does NOT match the logical session's bound
    /// identity is rejected `InvalidPubkey`, a LINK-ONLY INVALID(0x02) close is
    /// emitted on the secondary's own link, and — because the config-equality
    /// gate now runs BEFORE any link-set mutation — the primary's own link is NOT
    /// registered into the aggregation set (its single-link send path is
    /// untouched). Complements the e2e assertion 4, which drives `authorize_link`
    /// directly rather than `join_link`.
    #[cfg(feature = "codec-close")]
    #[test]
    fn join_link_rejects_tampered_pubkey_and_leaves_primary_untouched() {
        use crate::runtime_impl::TokioRuntime;
        use wz_runtime_core::Runtime;

        let (primary, _primary_driver) = crate::test_fixtures::recording_actions();
        let (secondary, secondary_driver) = crate::test_fixtures::recording_actions();

        // Bind the primary's logical-session identity to one ephemeral key and
        // give the secondary a TAMPERED captured key (differs in the last byte):
        // a genuine config-equality mismatch driven THROUGH join_link.
        let bound_key = vec![0x01u8, 0x02, 0x03, 0x04];
        let mut tampered = bound_key.clone();
        *tampered.last_mut().unwrap() ^= 0xFF;
        TokioRuntime::with_mutex_mut(&primary.core.multilink_pubkey, |s| *s = Some(bound_key));
        TokioRuntime::with_mutex_mut(&secondary.core.multilink_pubkey, |s| *s = Some(tampered));

        let outcome = join_link(&primary, &secondary, 2);
        assert!(
            matches!(outcome, JoinOutcome::InvalidPubkey),
            "a 2nd link whose captured pubkey mismatches the session identity is rejected INVALID"
        );

        // MF-D: the rejected join did NOT register the primary's own link, so the
        // existing single-link session's send path is unaffected.
        assert_eq!(
            primary.link_count(),
            0,
            "a rejected 2nd link does NOT register the primary's link (send path untouched)"
        );

        // A single LINK-ONLY INVALID(0x02) close was emitted on the secondary.
        assert_eq!(
            secondary_driver.frame_count(),
            1,
            "exactly one reject close on the secondary's own link"
        );
        let expected = wz_session_core::handshake_encode::encode_close(
            wz_session_core::extmultilink::CLOSE_REASON_INVALID,
            /*session=*/ false,
        );
        assert_eq!(
            secondary_driver.frame_bytes(0),
            expected,
            "the reject is a LINK-ONLY (S=0) close carrying zenoh reason INVALID (0x02)"
        );
    }
}

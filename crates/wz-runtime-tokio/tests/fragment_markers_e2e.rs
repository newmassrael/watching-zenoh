// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-unicast", feature = "codec-init-body"))]

//! R311y578 — the protocol PATCH level is genuinely NEGOTIATED over a real
//! handshake, and the Fragment chain-boundary markers arm from it.
//!
//! wz has emitted its own `0x7` patch extension since R121f1 and never read
//! the peer's, so the level a session ran at was unknowable from inside it.
//! That is not a cosmetic gap: `PatchType::has_fragmentation_markers()`
//! (`commons/zenoh-protocol/src/transport/mod.rs:333`) is the SOLE gate on
//! zenoh's Fragment `First` / `Drop` rules, so a wz that cannot read the
//! level can only ever leave those rules off.
//!
//! Two wz nodes handshake over loopback TCP. The assertion is on the
//! POST-handshake state of both peers, not on either one's intent: each side
//! must have taken a level FROM the wire (`patch_was_negotiated`), that level
//! must be `CURRENT_PATCH`, and the markers must therefore be armed. A
//! defaulted or seeded value fails the first of those, which is why the
//! `Option` behind `negotiated_patch` exists at all.

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;

use tokio::net::TcpListener;

const ITER_CAP: usize = 64;

/// Both sides of a real wz<->wz handshake come out with a NEGOTIATED patch
/// level of 1, and with the Fragment chain-boundary rules armed off it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_negotiates_the_patch_level_on_both_sides() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        let cfg = DialConfig::default();
        connect_and_open_session(
            locator,
            params,
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established")
    };
    let (opened_acc, opened_init) = tokio::join!(acc_open, init_open);

    for (who, actions) in [
        ("initiator", &opened_init.actions),
        ("acceptor", &opened_acc.actions),
    ] {
        // The level came off the WIRE. Without this the next assertion would
        // also pass on a session that had never seen an Init and simply kept
        // wz's own announcement.
        assert!(
            actions.patch_was_negotiated(),
            "{who} took its patch level from an admitted Init, not from a default"
        );
        assert_eq!(
            actions.negotiated_patch(),
            wz_session_core::extpatch::CURRENT_PATCH,
            "{who} negotiated min(local=1, peer=1) = 1"
        );
        assert!(
            actions.fragmentation_markers_negotiated(),
            "{who} arms the Fragment First/Drop chain-boundary rules at patch >= 1"
        );
    }
}

/// The negative arm the positive one needs: a peer that announces NO patch
/// extension drives the level to `NO_PATCH` and the markers stay off. Driven
/// through the same public negotiation entry the establishment demux calls,
/// with the peer's ext chain as the only input — an Init carrying no `0x7`
/// entry is exactly what `peer_patch` sees from a pre-patch peer.
///
/// Without this arm, "the markers are armed" could be an unconditional
/// `true` rather than a reading of the wire.
#[tokio::test]
async fn a_peer_without_the_patch_ext_leaves_the_markers_off() {
    use wz_session_core::extpatch::{peer_patch, NO_PATCH};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    let acc = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    });
    let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];
    let opened = connect_and_open_session(
        locator,
        params,
        &DialConfig::default(),
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("initiator reaches Established");
    let _acc = acc.await.expect("acceptor task");

    assert!(
        opened.actions.fragmentation_markers_negotiated(),
        "precondition: a wz peer negotiated patch 1"
    );
    // A pre-patch peer's Init carries no `0x7` entry at all.
    assert_eq!(peer_patch(&[]), NO_PATCH);
    opened.actions.negotiate_patch_against_peer(peer_patch(&[]));
    assert_eq!(
        opened.actions.negotiated_patch(),
        NO_PATCH,
        "min(1, 0) = 0 — the cap is monotonically non-increasing"
    );
    assert!(
        !opened.actions.fragmentation_markers_negotiated(),
        "a patch-0 peer emits no markers, so enforcing them would refuse every \
         chain it sends"
    );
}

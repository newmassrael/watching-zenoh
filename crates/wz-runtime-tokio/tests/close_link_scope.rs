// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-multilink",
    feature = "transport-link-tcp",
    feature = "codec-close",
))]

//! R311y839 — the SCOPE bit on a unicast Close: this LINK, or the whole SESSION?
//!
//! `FLAG_T_CLOSE_S` is the only field on a Close that says how much the peer is
//! meant to tear down, and zenoh's receiver branches on exactly it:
//! `TransportUnicastUniversal::handle_close` calls `delete()` when the bit is set
//! and `del_link(link)` when it is clear
//! (`io/zenoh-transport/src/unicast/universal/rx.rs:60-73`); `del_link` promotes
//! itself to a whole-transport close only once the link it removed was the last
//! (`unicast/universal/transport.rs:172-196`).
//!
//! wz was blind to that bit in BOTH directions. These tests were written against
//! that state and MEASURED it before the fix in the same commit; the values are
//! recorded here so the tests read as a standing gate rather than as a story.
//!
//! * SEND — both emit sites passed a literal `session = true`, while the FSM's
//!   `Closing` teardown is PER-LINK: its sibling `release_link` action removes
//!   only this link from the aggregation set (`del_link(&a.link)`). So a wz
//!   session tearing one link out of an aggregate told the peer to delete the
//!   whole transport, and then kept sending on the links it still held. Measured
//!   on a real two-link aggregate: the Close on the departing link was `[23, 00]`
//!   -- S SET. It is `[03, 00]` now, and `close_scope_is_session` derives it.
//! * RECEIVE — `InboundFrame::Close` carried `reason` and the ext chain but no
//!   scope, and the decode arm never read the parent flags even though the same
//!   function reads `FLAG_T_OPEN_A` and `FLAG_T_FRAME_R` a few arms away.
//!   Measured: `[03, 00]` and `[23, 00]` BOTH decoded to
//!   `Close { reason: 0, has_ext: false, extensions: [] }` -- the same value, so
//!   no consumer could act on the difference.
//!
//! # Reachability, measured rather than asserted
//!
//! The receive half is reachable against a STOCK zenoh peer in the ordinary case,
//! not a corner one: every unicast Close zenoh 1.5.0 constructs carries
//! `session: false`. All three sites —
//!
//! * `TransportLinkUnicast::close`, the establishment / link-level close
//!   (`unicast/link.rs:103-113`), which `accept.rs:717` reaches on every
//!   handshake rejection;
//! * `TransportUnicastUniversal::close`, the USER-triggered whole-transport close
//!   (`unicast/universal/transport.rs:383-403`) — whose own comment records the
//!   choice: "session should always be true for user-triggered close. However, in
//!   case of multiple links, it is safer to close all the links first";
//! * `TransportUnicastLowlatency::finalize` (`unicast/lowlatency/transport.rs:91-108`)
//!
//! — pass `session: false`, and that is not a source-only claim: a real zenohd
//! answered `[03, 02]` to a rejected handshake, S clear, measured off a socket by
//! `wz-integration-tests/tests/close_scope_zenohd_witness.rs`.
//!
//! The send half was symmetric and destructive in the other direction: wz's S=1
//! on a per-link teardown makes a zenohd `delete()` the transport wz still
//! believes it holds on its other links.
//!
//! # Why the single-link byte is NOT changed here, stated rather than hidden
//!
//! The two references DISAGREE on the last-link case and BOTH are reachable, so
//! it is not decidable the way the multilink case is. zenoh-pico's
//! `_z_unicast_transport_close` passes `link_only = false`, which SETS the flag
//! (`src/transport/unicast/transport.c:322-324` -> `_z_t_msg_make_close`,
//! `src/protocol/definitions/transport.c:227-237`), and it is live code — its
//! caller is the lease task (`src/transport/unicast/lease.c:99`). It is also the
//! byte wz already sends and every existing Close fixture pins.
//!
//! What makes deferring it SAFE rather than merely convenient is that the choice
//! is unobservable to both receivers on a single-link session: zenoh's `del_link`
//! on the only link closes the transport anyway, and zenoh-pico ignores the bit
//! entirely on receive — its Close arm returns `_Z_ERR_CONNECTION_CLOSED` without
//! looking at the header (`src/transport/unicast/rx.c:309-316`). The multilink
//! case is where the bit changes an outcome, and that case has one answer.

use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

use wz_runtime_tokio::config::LinkReliabilityPref;
use wz_runtime_tokio::multilink::{join_link, JoinOutcome};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_multilink, initiate_and_open_session_with_multilink, DialedLink,
    OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::{LinkDriver, LinkEvent};
use wz_runtime_tokio_test_support::fixture_params_with_zid;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_core::qos::Priority;
use wz_session_core::wire_const;

/// The two Close headers a peer can put on the wire, distinguished ONLY by
/// `FLAG_T_CLOSE_S`. Reason byte 0x00 (GENERIC) on both so the scope bit is the
/// single difference — a decoder that loses it renders these identical.
const LINK_ONLY_CLOSE: [u8; 2] = [wire_const::T_MID_CLOSE, 0x00];
const SESSION_CLOSE: [u8; 2] = [wire_const::T_MID_CLOSE | wire_const::FLAG_T_CLOSE_S, 0x00];

/// The drive-iteration cap the sibling multilink e2es use.
const ITER_CAP: usize = 8192;

/// RECEIVE half. The production parser must carry the scope off the wire.
///
/// Read through `parse_inbound` — the same function the drive loop hands every
/// inbound batch — rather than through a header-byte accessor, because the
/// question is what a wz session KNOWS after decoding, not what the bytes held.
#[test]
fn a_peers_link_only_close_decodes_differently_from_a_session_close() {
    let link_only = parse_inbound(&LINK_ONLY_CLOSE).expect("wz parses a link-only Close");
    let session = parse_inbound(&SESSION_CLOSE).expect("wz parses a session Close");

    match (&link_only, &session) {
        (InboundFrame::Close { .. }, InboundFrame::Close { .. }) => {}
        other => panic!("both headers are Close frames, got {other:?}"),
    }

    assert_ne!(
        format!("{link_only:?}"),
        format!("{session:?}"),
        "a link-only Close and a session Close must not decode to the same value \
         -- zenoh branches delete() vs del_link() on exactly this bit \
         (universal/rx.rs:60-73), so a decoder that drops it cannot honour either",
    );
}

/// RECEIVE half, projected. The scope a peer asked for, as a consumer reads it
/// off the decode rather than off the header byte.
#[test]
fn the_decoded_close_scope_matches_the_flag_the_peer_set() {
    let link_only = parse_inbound(&LINK_ONLY_CLOSE).expect("wz parses a link-only Close");
    let session = parse_inbound(&SESSION_CLOSE).expect("wz parses a session Close");

    assert_eq!(
        decoded_scope(&link_only),
        Some(false),
        "S clear = drop THIS LINK only -- zenoh's del_link(link)",
    );
    assert_eq!(
        decoded_scope(&session),
        Some(true),
        "S set = drop the whole session -- zenoh's delete()",
    );
}

/// Project the scope out of a decoded Close. `None` for any other frame.
fn decoded_scope(frame: &InboundFrame) -> Option<bool> {
    match frame {
        InboundFrame::Close { session, .. } => Some(*session),
        _ => None,
    }
}

/// The scope bit as it sits on the WIRE — what a peer's decoder reads.
///
/// The send-half assertions go through this rather than through wz's own
/// decoder: the emitted bytes are the thing under test, and reading them back
/// with the projection the fix adds would assert the fix against itself.
fn wire_scope(bytes: &[u8]) -> bool {
    assert_eq!(
        bytes.first().map(|h| h & 0x1F),
        Some(wire_const::T_MID_CLOSE),
        "expected a Close header, got {bytes:02X?}",
    );
    bytes[0] & wire_const::FLAG_T_CLOSE_S != 0
}

/// SEND half. A link leaving an AGGREGATE must announce a link-only close.
///
/// Built on the production join path (`join_link`) over real loopback sockets
/// rather than a hand-populated link set: the recurring defect in this tree is a
/// fixture asserting against a state production cannot reach, so the aggregate
/// under test is the one `--max-links 2` actually produces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_leaving_an_aggregate_announces_a_link_only_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let (_b1, a1) = open_link(&listener, 0x02, 0x01).await;
    let (mut b2, a2) = open_link(&listener, 0x02, 0x01).await;

    let a_primary = a1.actions.clone();
    let a_secondary = a2.actions.clone();
    let a_joined = match join_link(&a_primary, &a_secondary, 2) {
        JoinOutcome::Joined(handle) => handle,
        JoinOutcome::InvalidPubkey => panic!("the second link must aggregate, got InvalidPubkey"),
        JoinOutcome::OverLimit => panic!("the second link must aggregate, got OverLimit"),
    };
    assert_eq!(
        a_primary.link_count(),
        2,
        "precondition: A holds ONE session over TWO links",
    );

    // Tear the SECOND link down through the same primitive the signal-cancel
    // path uses. The session survives on link 1 by construction -- `release_link`
    // removes only this link from the shared set -- so the peer must be told to
    // drop the link, not the transport.
    a_joined.send_close_with_reason(CloseReason::Generic);

    let close = read_close_from(&mut b2).await;
    assert!(
        !wire_scope(&close),
        "the aggregate still holds link 1, so link 2's close is LINK-ONLY: \
         S=1 here makes a zenohd delete() a transport wz keeps sending on \
         (universal/rx.rs:60-73); got {close:02X?}",
    );
}

/// SEND half, control. The SAME primitive on a session that holds ONE link is a
/// whole-session close, and stays the byte wz already sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_only_link_of_a_session_still_announces_a_session_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let (mut b1, a1) = open_link(&listener, 0x02, 0x01).await;

    a1.actions.send_close_with_reason(CloseReason::Generic);

    let close = read_close_from(&mut b1).await;
    assert!(
        wire_scope(&close),
        "one link means closing it IS closing the session; got {close:02X?}",
    );
}

/// Open ONE loopback link, both sides Established with the multilink handshake.
async fn open_link(
    listener: &TcpListener,
    acc_zid: u8,
    init_zid: u8,
) -> (OpenedSession, OpenedSession) {
    let addr = listener.local_addr().expect("local_addr");
    let acc = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session_with_multilink(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(acc_zid),
            LinkReliabilityPref::Reliable,
            false,
            (Priority::Control, Priority::Background),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established (multilink)")
    };
    let init = async {
        let stream = TcpStream::connect(addr).await.expect("dial loopback");
        initiate_and_open_session_with_multilink(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(init_zid),
            LinkReliabilityPref::Reliable,
            false,
            (Priority::Control, Priority::Background),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established (multilink)")
    };
    tokio::join!(acc, init)
}

/// Pull inbound batches off `peer`'s real socket until one leads with a Close,
/// and return that batch's RAW bytes.
async fn read_close_from(peer: &mut OpenedSession) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "no Close arrived on the peer's link within the budget",
        );
        let event = tokio::time::timeout(remaining, peer.inbound.poll_event())
            .await
            .expect("peer link delivers a Close before the deadline");
        match event {
            LinkEvent::Rx(frame) => {
                if frame.bytes.first().map(|h| h & 0x1F) == Some(wire_const::T_MID_CLOSE) {
                    return frame.bytes;
                }
            }
            LinkEvent::Lost { .. } => panic!("peer link dropped before a Close frame arrived"),
            _ => {}
        }
    }
}

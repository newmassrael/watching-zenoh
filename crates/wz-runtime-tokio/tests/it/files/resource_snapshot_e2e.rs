// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "resource-snapshot", feature = "transport-unicast"))]

//! `resource-snapshot` (`docs/observation-plane.md` M4) — a real driven session spaces the
//! transport messages it receives.
//!
//! Two wz nodes handshake over a loopback TCP link to Established, as the `transport-stats`
//! end-to-end test does. Every inbound unit goes through the receive path's one counting seam, so
//! by Established each side has received the handshake's messages and spaced the ones after the
//! first. With `transport-stats` also on, the two instruments must name the same messages, since
//! one seam feeds both.

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;

use tokio::net::TcpListener;

const ITER_CAP: usize = 64;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handshake_is_received_and_spaced() {
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

    for (who, opened) in [("initiator", &opened_init), ("acceptor", &opened_acc)] {
        let reading = opened.message_reading();
        // InitSyn/InitAck/OpenSyn/OpenAck: each side received at least two.
        assert!(
            reading.messages >= 2,
            "{who} counted >=2 received messages ({reading:?})"
        );
        let spaced: u64 = reading.intervals.iter().sum();
        assert!(
            spaced >= 1,
            "{who}: the second message is spaced from the first ({reading:?})"
        );
        assert!(
            spaced < reading.messages,
            "{who}: the first message has no interval, so fewer intervals than messages ({reading:?})"
        );
        // The handshake takes a few milliseconds over loopback; a span of whole seconds would be a
        // clock read on the wrong epoch.
        assert!(
            reading.interval_sum_us < 5_000_000,
            "{who}: the handshake's messages are not seconds apart ({reading:?})"
        );

        #[cfg(feature = "transport-stats")]
        assert_eq!(
            reading.messages,
            opened.stats().rx.t_msgs as u64,
            "{who}: one seam feeds both counters, so they name the same messages"
        );
    }
}

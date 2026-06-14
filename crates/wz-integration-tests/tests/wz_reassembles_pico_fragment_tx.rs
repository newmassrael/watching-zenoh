// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311nk — FOREIGN-INTEROP unicast fragmentation: a zenoh-pico `z_put`
//! sends a payload that fragments on the wire and a watching-zenoh
//! acceptor reassembles it into one byte-exact Sample.
//!
//! This closes the cross-implementation half of the TX-fragmentation
//! proof. The existing coverage was:
//!
//! - `layer3_reassembly_tx.rs` (wz-runtime-tokio): wz -> wz, both ends this
//!   implementation, so it proves wz's own split + reassemble agree but NOT
//!   that a foreign sender's fragment chain decodes.
//! - `layer3_fragment.rs` (this crate): Fragment body byte-parity vs the
//!   zenoh-pico C codec — static, no socket.
//!
//! What was unverified: a REAL zenoh-pico process emitting a
//! `T_MID_FRAGMENT` chain over a live unicast TCP session, reassembled by
//! the wz RX path back into a single delivered Sample. That is this test.
//!
//! ## Why batch_size = 64 (and a 200-byte payload), not a large payload
//!
//! zenoh-pico fragments an outbound message when it exceeds the NEGOTIATED
//! unicast batch size (min of the two peers' advertised `batch_size`;
//! `vendor/zenoh-pico/src/transport/unicast/transport.c:135-136,232-234`).
//! The wz acceptor advertises `batch_size = 64`, pico's own default is
//! `Z_BATCH_UNICAST_SIZE = 2048`, so the negotiated MTU is `min(64,2048) =
//! 64` and pico's 200-byte Put leaves the wire as a multi-chunk
//! `T_MID_FRAGMENT` chain.
//!
//! The naive alternative — keep the default batch and send a multi-kilobyte
//! payload — does NOT work: wz's MsgPut payload codec is bounded at
//! `sce:max-size="256"` (`sources/codecs/msg_put.scxml:111`, an MCU
//! bounded-collection invariant). A reassembled payload above 256 bytes is
//! rejected at re-parse with `Codec(TooManyElements)` and the session
//! closes. So the only interop-valid fragmentation regime is "small
//! negotiated MTU, payload within the 256-byte bound" — 200 bytes here,
//! which fragments at MTU 64 yet re-parses cleanly.
//!
//! ## Fragmentation precondition asserted by construction (R311nj lesson)
//!
//! The negotiated MTU is asserted == 64 before the delivery is awaited. A
//! behaviour-only assert ("a Sample arrived") could pass even if the split
//! never happened — e.g. if negotiation silently regressed and the whole
//! Put rode one frame. Pinning the MTU makes the fragment branch mandatory:
//! 200 bytes over MTU 64 cannot be a single frame. (Unlike the wz<->wz case
//! where both ends could co-regress, here pico's 2048 default is an external
//! fixed constant, so only the wz-advertised 64 is the live variable — the
//! assert guards exactly it.)

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use wz_integration_tests::common::{zenoh_pico_cli_binary, ChildGuard};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{accept_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/frag";
// Negotiated MTU; pico's 200-byte Put exceeds it and fragments. Within the
// wz MsgPut 256-byte payload bound so the reassembled frame re-parses.
const BATCH_SIZE: u16 = 64;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_put); Layer E runs via --ignored"]
async fn wz_acceptor_reassembles_pico_fragmented_put() {
    let z_put = zenoh_pico_cli_binary("z_put");
    // 200 bytes of distinctive ASCII, within the 256-byte MsgPut bound,
    // above the 64-byte negotiated MTU (so it fragments). Verified
    // byte-for-byte at the subscriber.
    let payload_str = "0123456789".repeat(20);
    assert_eq!(payload_str.len(), 200);

    // wz acceptor binds first so pico's client dial lands in the listen
    // backlog and `accept()` resolves it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");

    // Spawn the foreign initiator: zenoh-pico z_put in client mode against
    // the wz acceptor's TCP endpoint. It declares the keyexpr, then Puts the
    // 200-byte payload which fragments at the negotiated MTU 64.
    let mut z_put_child = ChildGuard::wrap(
        "z_put (zenoh-pico initiator)",
        Command::new(&z_put)
            .args([
                "-k",
                KEYEXPR,
                "-v",
                &payload_str,
                "-e",
                &format!("tcp/{addr}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenoh-pico z_put"),
    );

    // ── wz acceptor handshake (batch_size = 64). Mirrors wz-ap-demo's
    //    accept path (runner.rs) which `ap_demo_round_trip.rs` proves
    //    interoperates with a pico z_put client; the only delta here is the
    //    tiny advertised batch that forces pico to fragment.
    let (stream, _peer) = listener.accept().await.expect("accept pico client");
    let mut params = fixture_session_init_params();
    params.batch_size = BATCH_SIZE;
    let mut opened = accept_and_open_session(
        DialedLink::Tcp(stream),
        params,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("wz acceptor reaches Established against the pico z_put client");

    // Fragmentation precondition, by construction (see module doc): pico
    // min-negotiates to 64, so its 200-byte Put cannot ride a single frame.
    assert_eq!(
        opened.actions.negotiated_batch_mtu(),
        BATCH_SIZE as usize,
        "wz advertised batch=64; pico must min-negotiate to it so the 200-byte Put fragments"
    );

    // ── Subscriber on the acceptor's observer; byte-exact on the
    //    reassembled payload.
    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        let expect = payload_str.clone().into_bytes();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            assert_eq!(
                sample.payload(),
                &expect[..],
                "the reassembled pico fragment chain matches the Put payload byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    let timeouts = SessionTimeouts::spec_defaults();
    // Continuous drive (None) so the RX reassembly pool persists across the
    // fragment chain's arrivals; select! drops it once the delivery lands.
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );

    // pico's `z_put` is one-shot: it Puts the (fragmented) payload then
    // closes the session, so the wz drive loop legitimately reaches a
    // terminal state. By TCP ordering the whole fragment chain is delivered
    // and reassembled (firing the subscriber) BEFORE the peer-close frame is
    // processed in the same loop, so awaiting the terminal and THEN asserting
    // the delivery is race-free. (Polling a budget against the drive future
    // instead races the near-instant loopback close: the close can drive the
    // loop to terminal before the poll observes `fired`, which was flaky.)
    tokio::select! {
        _ = drive => {}
        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            panic!("wz drive did not terminate within 10s — pico z_put never closed the session?")
        }
    }

    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "exactly one reassembled delivery from pico's fragmented Put (drive reached terminal first)"
    );

    let _ = z_put_child.child_mut().kill();
    let _ = z_put_child.child_mut().wait();
}

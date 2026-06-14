// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311nk/R311nl — FOREIGN-INTEROP unicast fragmentation: a real zenoh-pico
//! `z_put` emits a `T_MID_FRAGMENT` chain over a live unicast TCP session and
//! a watching-zenoh acceptor reassembles it. Two cases:
//!
//! - [`wz_acceptor_reassembles_pico_fragmented_put`] (positive): a 200-byte
//!   Put (within wz's MsgPut payload bound) fragments at the negotiated MTU 64
//!   and reassembles into one byte-exact Sample.
//! - [`wz_acceptor_rejects_pico_put_over_payload_bound`] (negative): a
//!   257-byte Put (one past wz's 256-byte bound) reassembles but is rejected
//!   at re-parse with `TooManyElements`. This pins a real wz<->pico PARITY
//!   divergence — zenoh-pico has NO msg_put payload bound, so it can send
//!   payloads over 256B that wz structurally cannot accept (msg_put.scxml:111
//!   `sce:max-size="256"`, an MCU bounded-collection invariant).
//!
//! The static byte-parity (layer3_fragment.rs) and the wz<->wz reassembly
//! (wz-runtime-tokio/tests/layer3_reassembly_tx.rs) left the
//! foreign-sender real-socket case unproven; these tests close it.
//!
//! ## Why batch_size = 64 (small negotiated MTU)
//!
//! zenoh-pico fragments an outbound message when it exceeds the NEGOTIATED
//! unicast batch size (min of the two peers' advertised batch_size;
//! `vendor/zenoh-pico/src/transport/unicast/transport.c:135-136,232-234`). wz
//! advertises 64, pico's default is 2048, so the negotiated MTU is
//! `min(64,2048)=64` and any Put >64B leaves the wire as a fragment chain.
//! Sending a multi-kilobyte payload on the default batch instead is NOT a
//! valid alternative — the 256-byte payload bound rejects it regardless of
//! MTU; that path is exactly the negative case below.
//!
//! ## Fragmentation is PROVEN, not inferred (R311nj/R311nl lesson)
//!
//! Both tests count `DriverLoopOutcome::Fragment` events on the wz RX drive
//! loop and assert a multi-chunk chain (>=2). This is the structural
//! guarantee: wz's RX read is NOT bounded by the negotiated batch (a single
//! un-fragmented frame would also be received), so `negotiated_batch_mtu()`
//! alone only proves pico's fragmentation INPUT, not that pico actually
//! fragmented. Counting the Fragment outcomes proves the chain reached the RX
//! path. The positive case additionally asserts byte-exact payload; the
//! negative case asserts the re-parse rejection + zero delivery.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use wz_integration_tests::common::{zenoh_pico_cli_binary, ChildGuard};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{accept_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/frag";
// Negotiated MTU; any Put >64B fragments. 200B (positive) stays under the
// 256B MsgPut bound; 257B (negative) is one past it.
const BATCH_SIZE: u16 = 64;

/// A shell-safe (alphanumeric) non-trivial payload of `len` bytes. `z_put -v`
/// takes a C string, so raw non-printable bytes (the sibling
/// `layer3_reassembly_tx` uses `(i*13) as u8`) are out. The 62-char alphabet
/// stepped by a coprime stride (7) has period 62, coprime to the 64-byte MTU,
/// so a chunk-boundary reorder/duplicate/drop in reassembly cannot survive
/// byte-equality the way a short repeated pattern could.
fn shell_safe_payload(len: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let bytes: Vec<u8> = (0..len)
        .map(|i| ALPHABET[(i * 7) % ALPHABET.len()])
        .collect();
    String::from_utf8(bytes).expect("alphanumeric is valid UTF-8")
}

/// Observed RX-side counters from one pico `z_put` against the wz acceptor.
struct InteropOutcome {
    fragment_chunks: usize,
    parse_errors: usize,
    deliveries: usize,
    byte_exact: bool,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_put); Layer E runs via --ignored"]
async fn wz_acceptor_reassembles_pico_fragmented_put() {
    let payload = shell_safe_payload(200);
    let o = run_pico_put_against_wz_acceptor(&payload, true).await;

    assert!(
        o.fragment_chunks >= 2,
        "pico's 200B Put must arrive as a multi-chunk T_MID_FRAGMENT chain at MTU 64 (saw {})",
        o.fragment_chunks
    );
    assert_eq!(
        o.parse_errors, 0,
        "the reassembled 200B frame re-parses cleanly"
    );
    assert!(
        o.byte_exact,
        "the reassembled payload matches byte-for-byte"
    );
    assert_eq!(o.deliveries, 1, "exactly one reassembled delivery");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_put); Layer E runs via --ignored"]
async fn wz_acceptor_rejects_pico_put_over_payload_bound() {
    // 257 = one past wz's MsgPut 256-byte payload bound (msg_put.scxml:111).
    // pico (no such bound) fragments + sends it; wz reassembles the full chain
    // then rejects at re-parse with TooManyElements and closes. Pins the
    // wz<->pico PARITY divergence as a mechanical boundary guard.
    let payload = shell_safe_payload(257);
    let o = run_pico_put_against_wz_acceptor(&payload, false).await;

    assert!(
        o.fragment_chunks >= 2,
        "pico's 257B Put fragments and wz reassembles the chain (saw {}) before the bound rejects it",
        o.fragment_chunks
    );
    assert!(
        o.parse_errors >= 1,
        "the reassembled 257B payload exceeds wz's 256B MsgPut bound and is rejected at re-parse"
    );
    assert_eq!(
        o.deliveries, 0,
        "no Sample is delivered: the over-bound payload never reaches the subscriber"
    );
}

/// Drive one pico `z_put(payload)` against an in-test wz acceptor that
/// advertises `batch_size = 64`, returning the RX-side counters. When
/// `expect_match` is set, a byte-exact subscriber check feeds `byte_exact`.
async fn run_pico_put_against_wz_acceptor(payload: &str, expect_match: bool) -> InteropOutcome {
    let z_put = zenoh_pico_cli_binary("z_put");

    // wz acceptor binds first so pico's client dial lands in the listen
    // backlog and `accept()` resolves it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");

    // Foreign initiator: zenoh-pico z_put in client mode. It declares the
    // keyexpr, then Puts the payload which fragments at the negotiated MTU 64.
    let mut z_put_child = ChildGuard::wrap(
        "z_put (zenoh-pico initiator)",
        Command::new(&z_put)
            .args([
                "-k",
                KEYEXPR,
                "-v",
                payload,
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

    // wz acceptor handshake (batch_size = 64). Same accept path as wz-ap-demo
    // (runner.rs), which `ap_demo_round_trip.rs` proves interoperates with a
    // pico z_put client; the only delta is the tiny advertised batch.
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
    assert_eq!(
        opened.actions.negotiated_batch_mtu(),
        BATCH_SIZE as usize,
        "wz advertised batch=64; pico min-negotiates to it (fragmentation INPUT)"
    );

    let deliveries = Arc::new(AtomicUsize::new(0));
    let byte_exact = Arc::new(AtomicBool::new(true));
    let mut observer = ApplicationLayerObserver::new();
    {
        let deliveries = deliveries.clone();
        let byte_exact = byte_exact.clone();
        let expect = payload.as_bytes().to_vec();
        observer.subscribers.register(KEYEXPR, move |sample| {
            if expect_match && (sample.keyexpr() != KEYEXPR || sample.payload() != &expect[..]) {
                byte_exact.store(false, Ordering::SeqCst);
            }
            deliveries.fetch_add(1, Ordering::SeqCst);
        });
    }

    // RX-side fragment / parse-error observation: the structural proof that
    // pico actually fragmented (Fragment) and, in the negative case, that the
    // reassembled frame was rejected (ParseError).
    let fragment_chunks = Arc::new(AtomicUsize::new(0));
    let parse_errors = Arc::new(AtomicUsize::new(0));
    let timeouts = SessionTimeouts::spec_defaults();
    let drive = {
        let fragment_chunks = fragment_chunks.clone();
        let parse_errors = parse_errors.clone();
        // Continuous drive (None) so the RX reassembly pool persists across
        // the fragment chain's arrivals.
        drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            move |event| {
                if let IterationEvent::Poll(outcome) = &event {
                    match outcome {
                        DriverLoopOutcome::Fragment { .. } => {
                            fragment_chunks.fetch_add(1, Ordering::SeqCst);
                        }
                        DriverLoopOutcome::ParseError(_) => {
                            parse_errors.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                }
                observer.dispatch_event(event)
            },
        )
    };

    // pico's z_put is one-shot (Put then close), so the wz drive legitimately
    // reaches a terminal state. By TCP ordering the whole fragment chain is
    // processed before the peer-close in the same loop, so awaiting the
    // terminal and reading the counters after is race-free (a polling budget
    // against the drive future races the near-instant loopback close).
    tokio::select! {
        _ = drive => {}
        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            panic!("wz drive did not terminate within 10s — pico z_put never closed the session?")
        }
    }

    let _ = z_put_child.child_mut().kill();
    let _ = z_put_child.child_mut().wait();

    InteropOutcome {
        fragment_chunks: fragment_chunks.load(Ordering::SeqCst),
        parse_errors: parse_errors.load(Ordering::SeqCst),
        deliveries: deliveries.load(Ordering::SeqCst),
        byte_exact: byte_exact.load(Ordering::SeqCst),
    }
}

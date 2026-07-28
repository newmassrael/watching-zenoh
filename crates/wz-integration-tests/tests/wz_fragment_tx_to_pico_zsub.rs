// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y206 — FOREIGN-INTEROP unicast fragmentation, SENDER direction: a
//! watching-zenoh publisher emits an oversize `Put` that fragments into a
//! `T_MID_FRAGMENT` chain on TX, and a real zenoh-pico `z_sub` reassembles
//! it into one byte-exact Sample.
//!
//! ## The gap this closes
//!
//! The reverse leg — a pico `z_put` fragment chain reassembled by a wz
//! acceptor — is proven in `wz_reassembles_pico_fragment_tx.rs` (wz as
//! RECEIVER). The wz↔wz TX split is proven in
//! `wz-runtime-tokio/tests/layer3_reassembly_tx.rs` (both sides wz). But
//! wz's OUTBOUND fragmenter had never been exercised against a NON-wz
//! reassembler: every existing wz→pico Put test sends a sub-MTU payload
//! (`wz_publisher_to_zsub.rs` = 13 B, `wz_e2e_pubsub_to_zsub.rs` = 20 B),
//! all under the negotiated batch, so they never fragment. This test
//! closes the bidirectional unicast-fragmentation interop cell: it proves
//! wz's `T_MID_FRAGMENT` wire encoding (fragment header + more-bit + SN)
//! is reassemblable by zenoh-pico's defrag path
//! (`vendor/zenoh-pico/src/transport/unicast/rx.c`).
//!
//! ## Why batch_size = 64 (fragmentation forced BY CONSTRUCTION)
//!
//! wz's TX split in `emit_frame_or_fragments` (session_actions.rs) branches
//! on `frame.len() > mtu`, where `mtu = negotiated_batch_mtu() = min(own,
//! peer)`. The wz acceptor advertises `batch_size = 64`; zenoh-pico's
//! default unicast batch is 2048, so the negotiated MTU is
//! `min(64, 2048) = 64` and a 200-byte Put's frame far exceeds it. The
//! test ASSERTS `negotiated_batch_mtu() == 64` before publishing (mirror of
//! `layer3_reassembly_tx.rs`'s R311nj precondition) so the split is
//! guaranteed by construction — a negotiation regression to the 65535
//! default would trip the assert, not silently pass with a single
//! un-fragmented frame. wz's decision to fragment is unit- and wz↔wz-proven;
//! what this test adds is the CROSS-IMPL proof that pico accepts the chain.
//!
//! ## Load-bearing invariant (this file cannot self-prove fragmentation)
//!
//! pico (not wz) is the receiver, so there is no wz-side fragment chunk count
//! to assert here — "wz actually fragmented" is by construction (MTU 64) AND
//! depends on `transport-fragmentation` being ON in this crate's
//! `wz-runtime-tokio` dev-dep (see `wz-integration-tests/Cargo.toml`). If that
//! pin were dropped, `emit_frame_or_fragments` would send one un-fragmented
//! frame that pico's 2048-byte RX buffer still accepts — a SILENT false pass
//! this file cannot self-detect (it carries no `#![cfg(...)]` gate, and the
//! feature lives on a DIFFERENT crate's dep, so no cross-crate test catches
//! THIS crate's pin drop). That pin-drop is an accepted residual: the pin is
//! broadly load-bearing (many wz-integration-tests frag lanes depend on it),
//! so it is not silently droppable in practice. What IS actively guarded is a
//! CODE regression in the shared split path (build_fragment_wire /
//! fragment_body / emit_frame_or_fragments): the host-lane
//! `wz-runtime-tokio/tests/layer3_reassembly_tx.rs` COUNTS the acceptor RX
//! fragment chunks (>= 2) at MTU 64, so a split-collapsing regression fails
//! there on every CI run without pico. Keep that assertion when touching the
//! emit path.
//!
//! ## Harness shape
//!
//! Mirrors `layer3_reassembly_tx.rs` (in-test wz sender, `Session::publish`
//! over the accepted session, `select!` drive-vs-scenario) crossed with
//! `wz_publisher_to_zsub.rs` (pico `z_sub` CLI, `stdbuf -oL` line-buffered
//! stdout capture, `>> [Subscriber] Received` witness). wz binds the
//! listener + acts as acceptor; pico `z_sub -m client` dials in and
//! subscribes `demo/**`. The scenario re-publishes the oversize Put on a
//! 150 ms cadence (so a Put lands after pico's DeclareSubscriber is live —
//! declare-ordering is handled by repetition, not by racing a single shot)
//! and polls pico's stdout until the full 200-byte payload appears
//! byte-exact. The wz drive loop runs in the same `select!` so each publish
//! is flushed to the wire and pico's declares/keepalives are serviced.

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use wz_integration_tests::common::{
    frag_payload, read_captured, zenoh_pico_cli_binary, ChildGuard,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{accept_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
// wz publishes on this leaf; pico subscribes the wildcard below so pico's
// receive-side literal-keyexpr (id=0 + suffix) resolver + local matcher fire.
const PUBLISH_KEYEXPR: &str = "demo/frag";
const SUB_KEYEXPR: &str = "demo/**";
// Negotiated MTU; a 200-byte Put fragments into a multi-chunk chain.
const BATCH_SIZE: u16 = 64;
// 200 B > 64 B MTU and within the alloc (AP) MsgPut owned-bytes bound.
const PAYLOAD_LEN: usize = 200;

// wz-proves: transport-fragmentation wz->pico partial
// wz-proves: pubsub-put wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_sub); Layer E runs via --ignored"]
async fn wz_tx_fragmented_put_reassembled_by_pico_zsub() {
    let payload = frag_payload(PAYLOAD_LEN);
    let z_sub = zenoh_pico_cli_binary("z_sub");

    // wz acceptor binds first so pico's client dial lands in the listen
    // backlog and `accept()` resolves it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Foreign reassembler: zenoh-pico z_sub in client mode, subscribing the
    // wildcard. `stdbuf -oL` forces line buffering so the "Received" witness
    // surfaces in near-real-time (printf to a piped fd is block-buffered by
    // default on glibc — the gotcha pinned by wz_publisher_to_zsub.rs).
    //
    // Accept + handshake WITH RETRY: pico's z_sub has a documented,
    // non-self-retrying one-shot open transient ("Unable to open session!").
    // Unlike wz_publisher_to_zsub.rs (a persistent wz-ap-demo listener), this
    // in-test topology accepts once per attempt, so a pico that dies
    // mid-handshake would fail `accept_and_open_session`. Respawn + re-accept
    // up to OPEN_ATTEMPTS so a rare foreign transient is a retry, not a red
    // build (no-flaky-ever). The common case succeeds on attempt 1.
    const OPEN_ATTEMPTS: usize = 6;
    let established = {
        let mut acc = None;
        for attempt in 1..=OPEN_ATTEMPTS {
            let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
            let z_sub_stdout_writer = z_sub_stdout.try_clone().expect("dup z_sub stdout handle");
            let z_sub_stdout_reader = z_sub_stdout;
            let mut z_sub_child = ChildGuard::wrap(
                "z_sub client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(&z_sub)
                    .args(["-k", SUB_KEYEXPR, "-e", &endpoint, "-m", "client"])
                    .stdout(Stdio::from(z_sub_stdout_writer))
                    .stderr(Stdio::inherit())
                    .spawn()
                    .expect("spawn z_sub via stdbuf"),
            );
            // wz acceptor handshake (batch_size = 64). The tiny advertised
            // batch is the only delta from wz_publisher_to_zsub.rs's proven
            // accept path; it forces the outbound fragmentation.
            let accepted = tokio::time::timeout(Duration::from_secs(8), listener.accept()).await;
            let stream = match accepted {
                Ok(Ok((stream, _peer))) => stream,
                _ => {
                    let _ = z_sub_child.child_mut().kill();
                    let _ = z_sub_child.child_mut().wait();
                    eprintln!(
                        "attempt {attempt}/{OPEN_ATTEMPTS}: pico did not connect within 8s; retrying"
                    );
                    continue;
                }
            };
            let mut params = fixture_session_init_params();
            params.batch_size = BATCH_SIZE;
            match accept_and_open_session(
                DialedLink::Tcp(stream),
                params,
                TokioTime::new(),
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            {
                Ok(opened) => {
                    acc = Some((opened, z_sub_child, z_sub_stdout_reader));
                    break;
                }
                Err(e) => {
                    let _ = z_sub_child.child_mut().kill();
                    let _ = z_sub_child.child_mut().wait();
                    eprintln!(
                        "attempt {attempt}/{OPEN_ATTEMPTS}: wz<->pico handshake failed ({e:?}); retrying"
                    );
                    continue;
                }
            }
        }
        acc.expect(
            "wz acceptor reached Established against a pico z_sub client within OPEN_ATTEMPTS",
        )
    };
    let (mut opened, mut z_sub_child, mut z_sub_stdout_reader) = established;

    // Fragmentation precondition, asserted BY CONSTRUCTION (mirror of
    // layer3_reassembly_tx.rs R311nj). With MTU 64 and a 200-byte payload
    // the publisher's `Session::publish` is FORCED through the fragment
    // branch; without this assert a negotiation regression to the 65535
    // default would deliver a single un-fragmented frame (which pico's
    // 2048-byte RX buffer would still accept) — a false positive.
    assert_eq!(
        opened.actions.negotiated_batch_mtu(),
        BATCH_SIZE as usize,
        "wz advertised batch=64; pico min-negotiates to it so the 200B Put fragments"
    );

    // Publisher over the accepted session's actions (Arc-shared). wz has no
    // local subscriber, so the publish loopback delivers nothing and the
    // proof is entirely pico's reassembled Sample. The drive loop below
    // borrows `&opened.actions`; the publisher holds an independent Arc
    // clone, so publish (interior-mutable enqueue) and the drive's shared
    // borrow do not conflict.
    let publisher = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );

    let timeouts = SessionTimeouts::spec_defaults();
    // wz-side observer for the drive loop — services pico's inbound
    // DeclareSubscriber + keepalives; no local subscriber is registered.
    let mut observer = ApplicationLayerObserver::new();
    // Continuous drive (None) so the outbound fragment chain is flushed and
    // the session persists across the republish cadence.
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );

    let received_witness = ">> [Subscriber] Received";
    let subscribed_witness = "Declaring Subscriber on";
    let scenario = async {
        // Gate the delivery budget on pico's subscriber-declared witness
        // BEFORE publishing, so pico's open latency (documented up to ~10s
        // under CI load) does not eat into the delivery deadline (no-flaky).
        // The drive loop (select! below) keeps the session alive while this
        // polls pico's line-buffered stdout.
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(subscribed_witness) {
                break;
            }
            if Instant::now() >= ready_deadline {
                return Err(format!(
                    "pico z_sub did not declare its subscriber within 10s \
                     (open transient / handshake issue?).\n\
                     --- captured z_sub stdout ---\n{captured}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // pico is subscribed; republish the oversize Put on a 150ms cadence
        // (idempotent, byte-identical) until pico prints the reassembled
        // payload. The loop defeats the inherent subscribe-before-publish race
        // deterministically — every Put is identical, so one landing after the
        // subscription is installed suffices; it is not flaky-masking retry.
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            publisher
                .publish(PUBLISH_KEYEXPR, payload.as_bytes(), PublishOptions::put())
                .expect("oversize publish builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(received_witness) && captured.contains(&payload) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_sub did not print the reassembled {PAYLOAD_LEN}B Put within 12s.\n\
                     Expected '{received_witness}' AND the full {PAYLOAD_LEN}B payload.\n\
                     --- captured z_sub stdout ---\n{captured}"
                ));
            }
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico received the reassembled Put"
        ),
        r = scenario => r,
    };

    // Tear down the pico child before asserting so a panic does not leak it.
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico TX-fragmentation interop FAILED.\n{msg}");
    }
}

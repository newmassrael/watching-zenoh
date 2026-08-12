// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "live")]

//! R311y702 ([REDACTED-REQ]) — THE LIVE LEG: the binary dials a real peer and that
//! peer decodes the samples the capture held.
//!
//! # What this proves that every earlier replay test cannot
//!
//! R311y700's tests drive the engine with a sink that RECORDS, which proves the
//! schedule and the mutations and proves nothing about whether anything is ever
//! sent. R311y701 added a real capture behind the extraction, which proves a
//! plan has real content and still sends nothing. The requirement is about
//! re-injection, and until this test the tool opened no socket at all.
//!
//! # Why the peer is a real wz session and the witness is what it DECODED
//!
//! A recording proxy would prove bytes moved; it would not prove they are a
//! session a conforming peer accepts. So the peer here runs the same
//! `accept_and_open_session` every wz acceptor runs, completes a real
//! handshake, and the assertion is on `DriverLoopOutcome::FramePayload` — the
//! messages its own transport decoded out of the frames that arrived.
//!
//! Reading the decoded messages rather than declaring a subscriber is
//! deliberate: `declare_subscriber` would pull the subscriber plane into this
//! crate's `wz` feature set, and Cargo unifies features across a build, so the
//! binary under test would silently be built with planes it does not pin. That
//! is the hazard `run_silent_acceptor_e2e` was written to avoid, one crate
//! over.

use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;

use wz::runtime_tokio::runtime_impl::TokioTime;
use wz::runtime_tokio::session_glue::{
    drive_session_until_terminal, DriverLoopOutcome, IterationEvent, NetworkMessage,
    SessionInitParams, SessionTimeouts, SigningKey, WhatAmI,
};
use wz::runtime_tokio::session_open::{
    accept_and_open_session, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};

/// Bound on the acceptor's inbound poll, so a handshake regression fails fast
/// instead of hanging the suite.
const ITER_CAP: usize = 4096;

/// What the peer decoded: a keyexpr and the payload under it.
type Heard = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_binary_dials_a_peer_and_that_peer_decodes_the_captured_samples() {
    let scratch = std::env::temp_dir().join(format!("wz-replay-live-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("a scratch directory");
    let capture = scratch.join("two.pcapng");
    std::fs::write(&capture, fixture::two_sample_capture()).expect("a fixture");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let heard: Heard = Arc::new(Mutex::new(Vec::new()));
    let recorder = heard.clone();

    // The acceptor's session engine is `!Send`, so it runs on THIS task rather
    // than a spawned one -- the arrangement every in-process handshake test in
    // this workspace uses.
    let acceptor = async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let clock = TokioTime::new();
        let OpenedSession {
            mut engine,
            actions,
            inbound,
            writer_handle,
            clock: _,
        } = accept_and_open_session(
            DialedLink::Tcp(stream),
            peer_init_params(),
            clock,
            None,
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("the replay tool opens a session this peer accepts");

        let mut driver = inbound;
        let timeouts = SessionTimeouts::spec_defaults();
        let _ = drive_session_until_terminal(
            &mut driver,
            &actions,
            &mut engine,
            Some(ITER_CAP),
            &clock,
            &timeouts,
            |event: IterationEvent<'_>| {
                let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event
                else {
                    return;
                };
                for message in messages {
                    if let Some(sample) = keyexpr_and_payload(message) {
                        recorder.lock().expect("not poisoned").push(sample);
                    }
                }
            },
        )
        .await;
        drop(actions);
        writer_handle.drain().await;
    };

    // The tool under test, as a PROCESS. `--gap 0` because the schedule has its
    // own tests and a live run that waited its default 100 ms per sample would
    // only make this test slower.
    let child = async {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_wz-replay"))
            .arg(&capture)
            .arg("--connect")
            .arg(format!("tcp/{addr}"))
            .arg("--gap")
            .arg("0")
            .output()
            .await
            .expect("the binary runs")
    };

    let (_, out) = tokio::join!(acceptor, child);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&scratch);

    assert!(
        out.status.success(),
        "the replay must exit clean: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("2 of 2 emission(s) sent to"),
        "and SAY how many of the plan reached the wire: {stdout}"
    );

    // THE CLAIM: the peer decoded the capture's own samples, by keyexpr and by
    // byte. A count alone would pass on a tool that published anything at all.
    let heard = heard.lock().expect("not poisoned").clone();
    assert_eq!(
        heard,
        vec![
            (String::from("demo/a"), b"first".to_vec()),
            (String::from("demo/b"), b"second".to_vec()),
        ],
        "the peer must receive exactly what the capture carried, in capture \
         order"
    );
}

/// R311y716 ([REDACTED-REQ]) — the ALERT reaches a real peer, and a clean capture
/// sends nothing to the same one.
///
/// The delivery half of the requirement, witnessed the only way that counts: a
/// process dials, a session opens, and a peer DECODES the notification. Both
/// arms run against the same acceptor in one test, because the two failures
/// they exclude are opposite and a suite that only proved the first would ship
/// a channel that cries wolf on every run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_alert_reaches_a_peer_and_a_clean_capture_sends_it_nothing() {
    let scratch = std::env::temp_dir().join(format!("wz-replay-alert-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("a scratch directory");
    // A record under a keyexpr id this capture never saw declared: read,
    // attributed to nothing, and so a capture whose totals are a floor.
    let short = scratch.join("aliased.pcapng");
    std::fs::write(&short, fixture::aliased_capture(false)).expect("a fixture");
    // And a capture with nothing wrong with it. Deliberately NOT one of the
    // reply fixtures: a reply whose request this capture never held is an
    // ORPHAN, so every one of them is short for a reason that has nothing to do
    // with what this arm is about. `clean_capture` exists for exactly that.
    let clean = scratch.join("clean.pcapng");
    std::fs::write(&clean, fixture::clean_capture()).expect("a fixture");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let heard: Heard = Arc::new(Mutex::new(Vec::new()));
    let recorder = heard.clone();

    let acceptor = async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let clock = TokioTime::new();
        let OpenedSession {
            mut engine,
            actions,
            inbound,
            writer_handle,
            clock: _,
        } = accept_and_open_session(
            DialedLink::Tcp(stream),
            peer_init_params(),
            clock,
            None,
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("the alert opens a session this peer accepts");

        let mut driver = inbound;
        let timeouts = SessionTimeouts::spec_defaults();
        let _ = drive_session_until_terminal(
            &mut driver,
            &actions,
            &mut engine,
            Some(ITER_CAP),
            &clock,
            &timeouts,
            |event: IterationEvent<'_>| {
                let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event
                else {
                    return;
                };
                for message in messages {
                    if let Some(sample) = keyexpr_and_payload(message) {
                        recorder.lock().expect("not poisoned").push(sample);
                    }
                }
            },
        )
        .await;
        drop(actions);
        writer_handle.drain().await;
    };

    let alerting = async {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_wz-replay"))
            .arg(&short)
            .arg("--alert")
            .arg("--alert-key")
            .arg("site/health")
            .arg("--connect")
            .arg(format!("tcp/{addr}"))
            .output()
            .await
            .expect("the binary runs")
    };

    let (_, out) = tokio::join!(acceptor, alerting);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "the alert must exit clean: {stdout}\n{stderr}"
    );
    // R311y750 (carry N3) — the delivery page, not the replay sink's line. It
    // is asserted with the DESTINATION and the ATTEMPT COUNT in it: one attempt
    // is the claim that the first dial reached a peer that was already up, and
    // a page saying `after 2 attempt(s)` here would mean the retry loop had
    // covered for a real defect on the way in.
    assert!(
        stdout.contains("delivery: 1 of 1 destination(s)"),
        "and say that it went: {stdout}"
    );
    assert!(
        stdout.contains(&format!("tcp/{addr} -- 1 emission(s) after 1 attempt(s)")),
        "naming the destination and what it took: {stdout}"
    );

    // THE CLAIM: the peer decoded the notification, under the operator's key,
    // and its body names the leg that was short. A count alone would pass on a
    // tool that published anything at all.
    let heard = heard.lock().expect("not poisoned").clone();
    assert_eq!(heard.len(), 1, "exactly one notification: {heard:?}");
    assert_eq!(
        heard[0].0, "site/health",
        "under the key the operator chose"
    );
    let body = String::from_utf8(heard[0].1.clone()).expect("utf-8");
    assert!(
        body.contains("\"complete\":false") && body.contains("unresolved_records"),
        "the peer must receive the REASON, not only that something is wrong: \
         {body}"
    );

    // THE OTHER HALF, against a fresh acceptor: a capture with nothing to
    // report must publish nothing. A channel that fires every run is ignored.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let quiet: Heard = Arc::new(Mutex::new(Vec::new()));
    let recorder = quiet.clone();
    let acceptor = async move {
        // A connection is never expected here, so the accept is RACED against
        // the tool finishing rather than awaited -- a bare await would hang the
        // suite on the behaviour this arm exists to prove.
        if let Ok(Ok((stream, _))) =
            tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await
        {
            drop(stream);
            recorder
                .lock()
                .expect("not poisoned")
                .push((String::from("<a session was opened at all>"), Vec::new()));
        }
    };
    let silent = async {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_wz-replay"))
            .arg(&clean)
            .arg("--alert")
            .arg("--connect")
            .arg(format!("tcp/{addr}"))
            .output()
            .await
            .expect("the binary runs")
    };
    let (_, out) = tokio::join!(acceptor, silent);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = std::fs::remove_dir_all(&scratch);
    assert!(
        out.status.success(),
        "a clean capture is not a failure: {stdout}"
    );
    assert!(
        stdout.contains("alert: none") && stdout.contains("nothing sent to"),
        "and the tool must SAY it sent nothing, so silence and not-running \
         never look alike: {stdout}"
    );
    assert!(
        quiet.lock().expect("not poisoned").is_empty(),
        "a complete capture must not even dial"
    );
}

/// R311y750 (carry N3) — the alert FANS to every destination, retries the one
/// that will not answer, and reports the shortfall as a failure.
///
/// # Why this is a separate test and not another arm of the one above
///
/// That test proves an alert reaches a peer. This one proves what happens when
/// one of the peers is not there, which is the case carry N3 was actually about
/// ("one transport, one destination, no retry -- right for a capture-file tool,
/// wrong for a watchdog"). The node an alert is ABOUT is often the node that
/// cannot forward it, so a watchdog with one destination has its single point of
/// failure exactly where the fault is.
///
/// # The three properties, and what each rules out
///
/// * `1 of 2` — the dead destination did not take the live one down with it. A
///   loop that stops at the first failure would deliver nothing here, and would
///   have passed a suite that only ever named reachable peers.
/// * `after 2 attempt(s)` on the dead one, `after 1` on the live one — the
///   retry ran, and it ran only where it was needed. A policy applied
///   unconditionally would show two attempts on both.
/// * exit 2 — a named destination that was not reached is a fault. A watchdog
///   that exits 0 with half its fan-out unreachable has taught its reader to
///   ignore the signal it exists to give.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_alert_fans_to_every_destination_and_retries_the_one_that_is_down() {
    let scratch = std::env::temp_dir().join(format!("wz-replay-fan-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("a scratch directory");
    let short = scratch.join("aliased.pcapng");
    std::fs::write(&short, fixture::aliased_capture(false)).expect("a fixture");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let live_addr = listener.local_addr().expect("local_addr");
    // A port nothing listens on: bound to learn a free one, then RELEASED. The
    // alternative -- a hard-coded port -- is the flaky one, because a port this
    // suite does not own may well have something on it.
    let dead_addr = {
        let doomed = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = doomed.local_addr().expect("local_addr");
        drop(doomed);
        addr
    };

    let heard: Heard = Arc::new(Mutex::new(Vec::new()));
    let recorder = heard.clone();

    let acceptor = async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let clock = TokioTime::new();
        let OpenedSession {
            mut engine,
            actions,
            inbound,
            writer_handle,
            clock: _,
        } = accept_and_open_session(
            DialedLink::Tcp(stream),
            peer_init_params(),
            clock,
            None,
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("the alert opens a session this peer accepts");

        let mut driver = inbound;
        let timeouts = SessionTimeouts::spec_defaults();
        let _ = drive_session_until_terminal(
            &mut driver,
            &actions,
            &mut engine,
            Some(ITER_CAP),
            &clock,
            &timeouts,
            |event: IterationEvent<'_>| {
                let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event
                else {
                    return;
                };
                for message in messages {
                    if let Some(sample) = keyexpr_and_payload(message) {
                        recorder.lock().expect("not poisoned").push(sample);
                    }
                }
            },
        )
        .await;
        drop(actions);
        writer_handle.drain().await;
    };

    let alerting = async {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_wz-replay"))
            .arg(&short)
            .arg("--alert")
            .arg("--connect")
            .arg(format!("tcp/{live_addr}"))
            .arg("--connect")
            .arg(format!("tcp/{dead_addr}"))
            .arg("--alert-retries")
            .arg("2")
            // Short on purpose: this is the retry SCHEDULE's only appearance in
            // wall-clock, and its shape is measured in `delivery`'s unit tests.
            .arg("--alert-backoff-ms")
            .arg("10")
            .output()
            .await
            .expect("the binary runs")
    };

    let (_, out) = tokio::join!(acceptor, alerting);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let heard = heard.lock().expect("not poisoned").clone();
    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(
        out.status.code(),
        Some(2),
        "a destination that was named and not reached is a failure: \
         {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("delivery: 1 of 2 destination(s)"),
        "the live destination must still have been delivered to: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "tcp/{live_addr} -- 1 emission(s) after 1 attempt(s)"
        )),
        "the reachable one takes ONE attempt: {stdout}"
    );
    assert!(
        stdout.contains(&format!("tcp/{dead_addr} -- FAILED after 2 attempt(s)")),
        "the unreachable one is retried to the policy's limit and then named: \
         {stdout}"
    );
    // AND THE PEER DECODED IT. Without this the assertions above could all hold
    // over a tool that printed a delivery page and sent nothing.
    assert_eq!(
        heard.len(),
        1,
        "the live peer must have decoded exactly one notification: {heard:?}"
    );
    assert_eq!(heard[0].0, "wz/alert", "under the default key");
}

/// R311y702 — a build without `live` REFUSES `--connect` instead of printing
/// the plan and exiting zero.
///
/// Not run here (this file is `live`-gated); the refusal is gated by run-ci's
/// C1by, which builds the binary with `--no-default-features` and drives it.
/// Recorded here so the two halves of the rule are readable in one place.
///
/// The rule: a lower layer that degrades silently when a feature is absent must
/// be turned into a refusal at the layer a person types into. An operator who
/// saw a plan and exit 0 would believe their replay went out.
#[test]
fn the_refusal_without_live_is_gated_by_the_lane_and_not_by_this_file() {}

/// Pull the keyexpr and payload out of one decoded message, for the Put shapes
/// a replay emits.
fn keyexpr_and_payload(message: &NetworkMessage) -> Option<(String, Vec<u8>)> {
    use wz_codecs::push::PushOwnedVariant;
    use wz_codecs::wireexpr::WireexprOwnedVariant;
    let NetworkMessage::Push(push) = message else {
        return None;
    };
    let put = match &push.body {
        PushOwnedVariant::CodecZenohMsgPut(m) | PushOwnedVariant::Default { body: m, .. } => m,
        PushOwnedVariant::CodecZenohMsgDel(_) => return None,
    };
    // A replay publishes a LITERAL keyexpr -- it declares no ids of its own --
    // so the suffix is the whole name and an id here would be a defect rather
    // than a case to resolve.
    // Two arms rather than an or-pattern: the local and nonlocal wire forms are
    // distinct types even though their fields read alike, which is the same
    // distinction `KeyexprSpaces::resolve` turns into a choice of TABLE.
    let (id, suffix) = match &push.keyexpr.body {
        WireexprOwnedVariant::WireexprLocal(a) => (a.id, a.suffix.as_deref()),
        WireexprOwnedVariant::WireexprNonlocal(a) => (a.id, a.suffix.as_deref()),
    };
    assert_eq!(id, 0, "a replay must publish literal keyexprs");
    Some((
        suffix.unwrap_or("").to_string(),
        put.payload.as_slice().to_vec(),
    ))
}

fn peer_init_params() -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        // Distinct from the replay tool's own zid, or the handshake is a node
        // talking to itself.
        zid: vec![0x02, 0x02, 0x02, 0x02],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 65535,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        cookie_signing_key: SigningKey::new(vec![0xAB; 32]).expect("32 bytes"),
    }
}

// The same two-sample capture the plan tests use, so what goes on the wire is
// something an earlier test already said the extraction reads.
mod fixture;

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y480 — the `preset-ap-full` COMPOSITION, driven against real zenoh-pico.
//!
//! ## The gap this closes
//!
//! Before this round `preset-ap-full` had no executable at all. Layer C4 ran
//! `cargo build -p wz --no-default-features --features preset-ap-full` — a
//! LIBRARY typecheck — and two separate comments in `run-ci.sh` say so in as many
//! words ("C4 builds preset-ap-full (which carries both) but is build-only and
//! clippy-free"; "preset-ap-full carries the features but is build-only").
//! `wz-ap-demo` had no `preset-ap-full` key, so `cargo build -p wz-ap-demo
//! --features preset-ap-full` answered
//!
//!     error: the package 'wz-ap-demo' does not contain this feature: preset-ap-full
//!
//! The kitchen-sink preset had therefore never been RUN, and no foreign peer had
//! ever spoken to it. Every pico proof in this crate drives a NARROW binary
//! instead — `--features routing-peer` (E6), `--features router-hat-router,time-hlc`
//! (E8t), `--features storage-backend` (E6e), and so on — so composition is the
//! one axis none of them can reach.
//!
//! ## Why composition is its own risk, not a formality
//!
//! `preset-ap-full` pulls 136 atoms into ONE binary, and among them are three the
//! inventory marks as NOT pico-faithful: `session-extqos` (reserved),
//! `session-extshm` (recorded WIRE-INCOMPATIBLE) and `transport-shm` (reserved).
//! A reserved atom is a declared cargo key with no cfg site, so the expectation is
//! that compiling it changes no wire byte — but that expectation had never been
//! tested against a real pico, because no build had ever composed them alongside
//! the live handshake. If any of the three had grown a cfg site that offered an
//! extension on InitSyn, a pico peer would refuse the session and every narrow
//! lane in this crate would still be green. Leg 1 is what makes that observable.
//!
//! ## The two legs, and which one pins the build
//!
//! * LEG 1 (`--listen` acceptor + real `z_put`) is the WIRE-INERTNESS witness: it
//!   proves the 136-feature composition still completes a zenoh-pico handshake and
//!   delivers a sample. It does NOT pin the build — the same assertion passes on
//!   the default `preset-ap-client` binary, which is exactly what
//!   `ap_demo_round_trip.rs` already runs. Stated plainly because a lane that
//!   silently built the wrong binary would pass this leg.
//!
//! * LEG 2 (`--peer` node between TWO real pico clients) is the BUILD
//!   DISCRIMINATOR. `--peer` is `cfg(feature = "routing-peer")`; a binary without
//!   it rejects the flag and exits 2 — the property
//!   `wz_peer_reject_without_feature.rs` asserts from the other side. So leg 2
//!   fails loudly against a `preset-ap-client` binary rather than passing
//!   vacuously, and it is the leg that certifies the lane built what it claims.
//!   Its delivery path is the CO-ATTACHED CLIENT egress, established by damage
//!   rather than by reading — see the fn-level comment.
//!
//! Together they are the composition proof: ONE process, two planes, three
//! foreign zenoh-pico processes, on the preset that until now only typechecked.
//!
//! ## Honest scope
//!
//! This does NOT prove the 136 atoms individually — most have no CLI surface on
//! the demo binary, and inventing one per atom would be a different (much larger)
//! round. What it proves is that composing them produces a binary that still
//! interoperates with a real foreign implementation on the planes the demo does
//! expose. The per-atom proofs remain where they already live, on their narrow
//! lanes.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::bounded::BoundedStatus as _;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured,
    spawn_on_ephemeral_port, spawn_publishing_zpub, spawn_subscribed_zsub, wait_for_substring,
    wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};
use wz_session_core::wire_const::{FLAG_T_INIT_A, FLAG_T_OPEN_A, T_MID_INIT, T_MID_OPEN};

/// How long the foreign exchange gets. Generous because the lane runs under
/// full-run-ci process pressure, and `wait_for_substring` returns the instant the
/// marker appears — a wide ceiling costs a green run nothing.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

/// Leg 1 — the composed AP-full binary still speaks zenoh-pico's client wire.
///
/// A real `z_put` opens a session against the kitchen-sink acceptor and its
/// sample reaches the registered subscriber. The load-bearing part is not the
/// round trip itself (that is `ap_demo_round_trip.rs`'s job on the ap-client
/// binary) but that it still happens with `session-extqos` / `session-extshm` /
/// `transport-shm` compiled in — the reserved, explicitly non-pico-faithful atoms
/// the kitchen sink drags along. If one of them ever offers an ext on InitSyn,
/// pico refuses the session and this leg reds.
// wz-proves: session-unicast-accept pico->wz
// wz-proves: pubsub-put pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico CLI); Layer E9 runs via --ignored"]
fn apfull_preset_acceptor_round_trips_with_a_real_pico_z_put() {
    let demo = wz_ap_demo_binary();
    let z_put = zenoh_pico_cli_binary("z_put");
    let key = "demo/apfull";

    let stderr = tempfile::tempfile().expect("tempfile for AP-full demo stderr");
    let (mut demo_guard, mut demo_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--listen", "127.0.0.1:0", "--key", "demo/**"],
        "listening on 127.0.0.1:",
        "wz-ap-demo (preset-ap-full, --listen)",
        stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // R311y606 — captured, not discarded: this exit status is ASSERTED,
    // and an asserted failure with no output is unanswerable.
    let mut capture = tempfile::tempfile().expect("zenoh-pico z_put capture");
    let put = Command::new(&z_put)
        .args([
            "-k",
            key,
            "-v",
            "hello-from-pico-to-apfull",
            "-e",
            &endpoint,
            "-m",
            "client",
        ])
        .stdout(Stdio::from(capture.try_clone().expect("dup stdout handle")))
        .stderr(Stdio::from(capture.try_clone().expect("dup stderr handle")))
        .status_bounded()
        .expect("spawn zenoh-pico z_put");
    assert!(
        put.success(),
        "the real zenoh-pico z_put exited {put:?} against the AP-full acceptor — \
         it could not complete the session handshake, which is the composition \
         failure this leg exists to catch\n--- its stdout+stderr ---\n{}",
        read_captured(&mut capture)
    );

    let fired = wait_for_substring(&mut demo_reader, "SUBSCRIBER FIRED", EXCHANGE_TIMEOUT);
    let outcome = fired.map(|c| c.to_string());
    graceful_terminate(demo_guard.child_mut(), Duration::from_secs(5));

    let captured = match outcome {
        Ok(c) => c,
        Err(c) => panic!(
            "the AP-full acceptor never logged 'SUBSCRIBER FIRED' for a real pico \
             z_put. The 136-feature composition broke a wire that every narrow \
             single-feature lane still reports green.\n--- wz-ap-demo stderr ---\n{c}"
        ),
    };
    assert!(
        captured.contains(key),
        "'SUBSCRIBER FIRED' appeared but not for {key} — the delivered sample was \
         not the one pico put\n--- wz-ap-demo stderr ---\n{captured}"
    );
}

/// Leg 2 — TWO real zenoh-pico clients interoperate THROUGH the composed AP-full
/// binary, and the leg doubles as the build discriminator.
///
/// `--peer` only exists under `cfg(feature = "routing-peer")`; a binary built
/// without it rejects the flag and exits 2 (the twin assertion in
/// `wz_peer_reject_without_feature.rs`). `spawn_on_ephemeral_port` is
/// liveness-aware, so that build fails here in ~0.1s with the child's exit status
/// named, rather than being mistaken for a slow bind. That is what stops this file
/// from certifying a lane that built the wrong binary.
///
/// The foreign edge is BOTH ends: neither publisher nor subscriber is a wz
/// process, so nothing in the exchange is wz agreeing with its own twin.
///
/// ## WHICH code this actually binds to — established by damage, not by reading
///
/// Both picos attach as CLIENTS of the one peer, so the delivery path is
/// `RouterForwarder::deliver_to_client_subscribers` (co-attached client
/// egress), NOT the mesh spanning-tree `forward_push`. That was MEASURED:
/// inverting the tree-forward target predicate in `forward_push` left this leg
/// GREEN, while inverting the `id == inbound` self-exclusion in
/// `deliver_to_client_subscribers` reds it. Recorded because the first wording of
/// this comment said "mesh data plane", which the damage refuted — a two-hop
/// mesh transit to a pico client is `wz_peer_transit_push_pico_interop.rs`'s
/// property, not this one's, and claiming it here would bind the claim to code
/// the leg never executes.
// wz-proves: routing-peer pico->wz partial
// wz-proves: declare-subscriber pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico CLI); Layer E9 runs via --ignored"]
fn apfull_preset_peer_forwards_between_two_real_pico_clients() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let sub_key = "demo/**";
    let pub_key = "demo/apfull/mesh";
    let payload = "APFULL-MESH-BETWEEN-TWO-PICOS";

    let stderr = tempfile::tempfile().expect("tempfile for AP-full peer stderr");
    let (mut peer_guard, mut peer_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--peer", "127.0.0.1:0"],
        "peer: listening on 127.0.0.1:",
        "wz-ap-demo (preset-ap-full, --peer)",
        stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // Subscriber FIRST: the helper returns only once pico has opened the session
    // AND declared, so the peer has the interest before any sample is emitted.
    let (mut sub_child, mut sub_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint, "the AP-full peer", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    // `z_pub -n 30` bursts over ~30s, so a subscription that is declared but not
    // yet installed on the peer's face costs a dropped sample, not a failed test.
    // A one-shot `z_put` here would race the interest propagation.
    let mut pub_child = spawn_publishing_zpub(
        &z_pub,
        pub_key,
        payload,
        &endpoint,
        "the AP-full peer",
        || tempfile::tempfile().expect("tempfile for z_pub stdout"),
    );

    let received = wait_for_substring(&mut sub_reader, payload, EXCHANGE_TIMEOUT);
    let outcome = received.map(|c| c.to_string());

    // The peer must have ACTUALLY routed it. Without this, a direct pico<->pico
    // path (were one ever possible) would satisfy the foreign assertion above and
    // the leg would prove nothing about wz.
    //
    // POLLED, not read once. The forwarder counts the push on its own app tick, so
    // the marker trails the subscriber's delivery — a single `read_captured` here
    // raced that write and read a log that stopped at `face 1 UP`, which is how
    // this assertion first failed against a run whose foreign witness had already
    // succeeded. Polled BEFORE the children are reaped so the peer is still alive
    // to write it.
    let routed = wait_for_substring(&mut peer_reader, "received mesh data", EXCHANGE_TIMEOUT)
        .map(|c| c.to_string());

    let _ = pub_child.child_mut().kill();
    let _ = pub_child.child_mut().wait();
    let _ = sub_child.child_mut().kill();
    let _ = sub_child.child_mut().wait();
    graceful_terminate(peer_guard.child_mut(), Duration::from_secs(5));
    let peer_log = read_captured(&mut peer_reader);

    let sub_out = match outcome {
        Ok(c) => c,
        Err(c) => panic!(
            "the real zenoh-pico z_sub never received '{payload}' through the \
             AP-full peer. Both endpoints are foreign, so the mesh data plane of \
             the composed preset did not forward.\n--- pico z_sub stdout ---\n{c}\
             \n--- AP-full peer stderr ---\n{peer_log}"
        ),
    };
    assert!(
        sub_out.contains(pub_key),
        "the payload arrived but not on {pub_key} — the forwarded sample carried \
         the wrong keyexpr\n--- pico z_sub stdout ---\n{sub_out}"
    );
    if let Err(c) = routed {
        panic!(
            "the pico subscriber got the sample but the AP-full peer never logged \
             'received mesh data' — the exchange did not go through wz's \
             forwarder\n--- AP-full peer stderr ---\n{c}"
        );
    }
}

/// How long one framed handshake message gets to arrive.
const HANDSHAKE_STEP: Duration = Duration::from_secs(10);

/// How long a replayed OpenSyn is watched for an OpenAck. The acceptor answers
/// an admitted OpenSyn at once (the control below measures that on the same
/// run), so this is several times what an answer takes.
const REPLAY_WINDOW: Duration = Duration::from_secs(3);

fn header(message: &[u8]) -> Option<u8> {
    message.first().copied()
}

fn is_init(message: &[u8], ack: bool) -> bool {
    header(message).is_some_and(|h| h & 0x1F == T_MID_INIT && (h & FLAG_T_INIT_A != 0) == ack)
}

fn is_open(message: &[u8], ack: bool) -> bool {
    header(message).is_some_and(|h| h & 0x1F == T_MID_OPEN && (h & FLAG_T_OPEN_A != 0) == ack)
}

/// Write one message with the streamed-link envelope: a 2-byte little-endian
/// length, then the bytes.
fn write_framed(stream: &mut TcpStream, message: &[u8]) {
    let len = u16::try_from(message.len()).expect("a handshake message fits the envelope");
    stream
        .write_all(&len.to_le_bytes())
        .expect("write the length prefix");
    stream.write_all(message).expect("write the message");
    stream.flush().expect("flush the message");
}

/// Read one enveloped message, or `None` at the end of the stream or when
/// `deadline` passes first.
fn read_framed_until(stream: &mut TcpStream, deadline: Instant) -> Option<Vec<u8>> {
    let left = deadline.checked_duration_since(Instant::now())?;
    stream
        .set_read_timeout(Some(left.max(Duration::from_millis(1))))
        .ok()?;
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).ok()?;
    let mut message = vec![0u8; usize::from(u16::from_le_bytes(len))];
    stream.read_exact(&mut message).ok()?;
    Some(message)
}

/// Every message `stream` carries until it ends or `deadline` passes.
fn read_all_until(stream: &mut TcpStream, deadline: Instant) -> Vec<Vec<u8>> {
    let mut messages = Vec::new();
    while let Some(message) = read_framed_until(stream, deadline) {
        messages.push(message);
    }
    messages
}

/// Accept one connection, or panic once `deadline` passes: a pico that never
/// dials must fail this leg, not hang it.
fn accept_until(listener: &TcpListener, deadline: Instant) -> TcpStream {
    listener
        .set_nonblocking(true)
        .expect("a non-blocking accept");
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("a blocking accepted stream");
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "the real zenoh-pico z_put never dialled the relay"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("accept the real zenoh-pico z_put: {e}"),
        }
    }
}

/// Open-debt item 179 — a cookie echoed on a handshake it was not minted for is
/// refused, witnessed with bytes a real zenoh-pico wrote.
///
/// The FSM-level twin (`session_fsm_accepting_path.rs`) replays a cookie wz's
/// own acceptor minted inside one process, against an OpenSyn this tree
/// crafted. Here the OpenSyn is a real pico's, captured off the wire, and the
/// acceptor is the composed AP-full node behind its accept loop. No stock
/// binary can be asked to replay a stale cookie, so the replayer is this test:
/// it relays a real pico's handshake to the node on link A, recording pico's
/// InitSyn and OpenSyn on the way, then plays those two messages on a second
/// link B.
///
/// Both halves are asserted on the same bytes and the same node: on A, the
/// handshake the OpenSyn belongs to, it is admitted; on B, whose InitAck minted
/// another cookie, it gets no OpenAck. So the refusal is the cookie binding and
/// not a broken acceptor or a malformed message. The relay on A does not pause:
/// the node's acceptor gives a whole handshake one second.
///
/// `--peer`, not `--listen`: a one-shot listener is consumed by its first
/// accept, and this leg needs a second link.
// wz-proves: session-unicast-accept pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico CLI); Layer E9 runs via --ignored"]
fn apfull_preset_acceptor_refuses_a_real_pico_open_syn_replayed_on_another_handshake() {
    let demo = wz_ap_demo_binary();
    // A stale demo would grade yesterday's acceptor, and a refusal from it would
    // read as today's.
    assert_demo_binary_newer_than_sources(&demo);
    let z_put = zenoh_pico_cli_binary("z_put");

    let stderr = tempfile::tempfile().expect("tempfile for AP-full peer stderr");
    let (mut peer_guard, mut peer_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--peer", "127.0.0.1:0"],
        "peer: listening on 127.0.0.1:",
        "wz-ap-demo (preset-ap-full, --peer, cookie replay target)",
        stderr,
    );

    // The relay pico dials instead of the node.
    let relay = TcpListener::bind("127.0.0.1:0").expect("bind the relay");
    let relay_port = relay.local_addr().expect("relay address").port();
    let pico_out = tempfile::tempfile().expect("tempfile for z_put output");
    let mut pico = ChildGuard::wrap(
        "z_put (zenoh-pico, through the replaying relay)",
        Command::new(&z_put)
            .args([
                "-k",
                "demo/apfull/replay",
                "-v",
                "a-handshake-to-replay",
                "-e",
                &format!("tcp/127.0.0.1:{relay_port}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::from(pico_out.try_clone().expect("dup z_put stdout")))
            .stderr(Stdio::from(pico_out.try_clone().expect("dup z_put stderr")))
            .spawn()
            .expect("spawn zenoh-pico z_put"),
    );
    let mut from_pico = accept_until(&relay, Instant::now() + HANDSHAKE_STEP);

    // LINK A, THE CONTROL: relay pico's handshake to the node and record pico's
    // OpenSyn on the way. The node admits it here, on the handshake whose cookie
    // it echoes. Relayed without a pause: the node's acceptor gives a whole
    // handshake one second.
    let mut link_a = TcpStream::connect(("127.0.0.1", port)).expect("dial the node (link A)");
    let init_syn = read_framed_until(&mut from_pico, Instant::now() + HANDSHAKE_STEP)
        .expect("the real pico opens with an InitSyn");
    assert!(
        is_init(&init_syn, false),
        "pico's first message: {init_syn:02X?}"
    );
    write_framed(&mut link_a, &init_syn);
    let init_ack_a = read_framed_until(&mut link_a, Instant::now() + HANDSHAKE_STEP)
        .expect("the node answers pico's InitSyn on link A");
    assert!(
        is_init(&init_ack_a, true),
        "link A's answer: {init_ack_a:02X?}"
    );
    write_framed(&mut from_pico, &init_ack_a);
    let open_syn = read_framed_until(&mut from_pico, Instant::now() + HANDSHAKE_STEP)
        .expect("the real pico echoes the cookie in an OpenSyn");
    assert!(
        is_open(&open_syn, false),
        "pico's second message: {open_syn:02X?}"
    );
    write_framed(&mut link_a, &open_syn);
    let control_answer = read_framed_until(&mut link_a, Instant::now() + HANDSHAKE_STEP);
    if let Some(answer) = &control_answer {
        write_framed(&mut from_pico, answer);
    }
    drop(link_a);
    drop(from_pico);
    let _ = pico.child_mut().kill();
    let _ = pico.child_mut().wait();

    // LINK B, THE REPLAY: pico's own InitSyn mints a new cookie, then the OpenSyn
    // that echoes link A's.
    let mut link_b = TcpStream::connect(("127.0.0.1", port)).expect("dial the node (link B)");
    write_framed(&mut link_b, &init_syn);
    let init_ack_b = read_framed_until(&mut link_b, Instant::now() + HANDSHAKE_STEP);
    if init_ack_b.is_some() {
        write_framed(&mut link_b, &open_syn);
    }
    let replay_answers = read_all_until(&mut link_b, Instant::now() + REPLAY_WINDOW);
    drop(link_b);

    graceful_terminate(peer_guard.child_mut(), Duration::from_secs(5));
    let peer_log = read_captured(&mut peer_reader);

    assert!(
        control_answer.as_deref().is_some_and(|m| is_open(m, true)),
        "the control failed: pico's OpenSyn was not admitted even on the handshake \
         it was minted for, so a refusal on link B would say nothing about the cookie. \
         link A answered {control_answer:02X?}\n--- AP-full peer stderr ---\n{peer_log}"
    );
    let Some(init_ack_b) = init_ack_b else {
        panic!(
            "the node did not answer pico's InitSyn on link B, so the replay was never \
             made\n--- AP-full peer stderr ---\n{peer_log}"
        );
    };
    assert!(
        is_init(&init_ack_b, true),
        "link B's answer: {init_ack_b:02X?}"
    );
    assert_ne!(
        init_ack_b, init_ack_a,
        "the two handshakes must mint different cookies, or the replay cannot be \
         told from an honest open"
    );
    let headers: Vec<Option<u8>> = replay_answers.iter().map(|m| header(m)).collect();
    assert!(
        !replay_answers.iter().any(|m| is_open(m, true)),
        "a real pico's OpenSyn, echoing the cookie of another handshake, was admitted \
         on link B: the replay the per-handshake cookie closes is open. \
         link B answered headers {headers:02X?}\n--- AP-full peer stderr ---\n{peer_log}"
    );
}

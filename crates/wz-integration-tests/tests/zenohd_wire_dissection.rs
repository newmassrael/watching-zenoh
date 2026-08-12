// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y760 (carry N65) — the analyzer against the OTHER reference
//! implementation: stock zenoh 1.5.0 Rust, as a real `zenohd`.
//!
//! ## Why zenoh-pico coverage was not evidence about this
//!
//! R311y759 pointed the dissector at bytes a real `libzenohpico` wrote, which
//! closed the "every witness is self-authored" hole. It did NOT close it for
//! zenohd, and the register said so as carry N65 rather than letting the pico
//! result stand in: the two reference implementations are separate encoders, and
//! they diverge exactly where this workspace's grading is thinnest. A pico client
//! emits a client's message set; a router emits a router's.
//!
//! The roles also swap, which is the structural half of the difference. In the
//! pico witness the foreign process DIALLED and wz accepted, so the foreign half
//! of the capture was a client's. Here wz dials and `zenohd` accepts, so the
//! foreign half is the one a ROUTER writes — the acceptor side of the handshake
//! and whatever it declares back. Nothing in this tree had ever handed those
//! bytes to `wz-capture`.
//!
//! ## Shared harness, deliberately
//!
//! The relay and the pcap synthesis live in `wz_integration_tests::wire_tap`, not
//! in this file. The envelope rules (link type, per-direction sequence numbers)
//! are ONE fact, and a second copy would drift the first time a witness needed a
//! different link — the same reasoning that put the inventory kind predicate in
//! one module after four copies of it had already caused a defect.
//!
//! ## Stock and synthesised, stated as in the pico witness
//!
//! STOCK: every byte above TCP, both directions, the acceptor half written by
//! stock zenohd. SYNTHESISED: the Ethernet / IPv4 / TCP envelope, because a
//! userspace relay cannot see headers the kernel wrote.
//!
//! ## What the first run found
//!
//! `zenohd -> wz` dissected as `[Init, Open, Frame, Frame, Frame]` and
//! `wz -> zenohd` as `[Init, Open]`. THE THREE ROUTER-SIDE FRAMES ARE THE POINT:
//! a pico client emits nothing of the kind, so no witness in this tree had ever
//! handed the dissector a message a router chose to send. Every one parsed.
//!
//! The asymmetry is also honest evidence and is NOT asserted away: wz's own
//! `--publish` does not appear as a Frame in this capture, so the sample either
//! left after the teardown or never left at all. That is carried rather than
//! papered over — this witness is about what zenohd emits, and reading the wz
//! half as complete would be a claim the capture does not support.
//!
//! ## Falsification
//!
//! Bypassing the tap (dialling zenohd directly) reds with `the tap never saw
//! both directions`, so "the relay is on the path" is measured rather than
//! assumed — the session succeeds either way, and only the recording tells them
//! apart. The shared harness's other probes (empty recording, damaged segment)
//! were measured in the pico witness against the same code.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_capture::Dissection;
use wz_integration_tests::common::{
    read_captured, wait_for_tcp_accept_alive, wz_ap_demo_binary, zenohd_binary, ChildGuard,
    PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Recording, Side};
use wz_session_core::inbound::InboundFrame;
use wz_session_core::passive::Direction;

/// A short name for a parsed transport message.
///
/// EXHAUSTIVE (no `_ =>`): this witness reports what a foreign encoder actually
/// emitted, and a catch-all would file a brand-new message type as "something".
fn frame_name(frame: &InboundFrame) -> &'static str {
    match frame {
        InboundFrame::Init { .. } => "Init",
        InboundFrame::Open { .. } => "Open",
        InboundFrame::Close { .. } => "Close",
        InboundFrame::KeepAlive { .. } => "KeepAlive",
        InboundFrame::Frame { .. } => "Frame",
        InboundFrame::Fragment { .. } => "Fragment",
        InboundFrame::Join { .. } => "Join",
        InboundFrame::Unknown { .. } => "Unknown",
    }
}

/// Wait until BOTH directions have carried bytes, which is the earliest point a
/// handshake can have completed.
///
/// Polling the recording rather than a log line on purpose: the marker is then
/// the same artefact the assertions read, so a run that reaches the assertions
/// cannot have raced a message the tap had not yet seen.
fn wait_for_both_directions(recording: &Recording, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        {
            let segments = recording.lock().expect("recording lock");
            let dialer = segments.iter().any(|(s, _)| *s == Side::FromDialer);
            let listener = segments.iter().any(|(s, _)| *s == Side::FromListener);
            if dialer && listener {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// THE WITNESS: a real zenohd session, relayed and dissected.
// wz-proves: session-unicast-open wz->zenohd
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenohd); Layer Ewirez runs via --ignored"]
fn the_analyzer_parses_every_message_a_real_zenohd_puts_on_the_wire() {
    let demo = wz_ap_demo_binary();
    let reservation = PortReservation::pick();
    let zenohd_port = reservation.port();

    let mut zenohd = ChildGuard::wrap(
        "zenohd (behind the tap proxy)",
        Command::new(zenohd_binary())
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{zenohd_port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenohd"),
    );
    let accepted =
        wait_for_tcp_accept_alive(zenohd.child_mut(), zenohd_port, ZENOHD_TCP_ACCEPT_BUDGET);
    if let Err(e) = accepted {
        panic!("zenohd never accepted: {e}");
    }

    let (proxy_port, recording) = tap_proxy(zenohd_port);

    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_writer = demo_stderr.try_clone().expect("dup demo stderr");
    let mut demo_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect through the tap proxy)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{proxy_port}"))
            .arg("--publish")
            .arg("demo/tapped")
            .arg("--value")
            .arg("hello-through-the-tap")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect"),
    );

    let both = wait_for_both_directions(&recording, Duration::from_secs(15));
    // Let the post-handshake exchange settle before tearing down; without it the
    // capture can end mid-declare and the message census below would describe the
    // teardown rather than the session.
    std::thread::sleep(Duration::from_millis(500));
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    std::thread::sleep(Duration::from_millis(200));

    let demo_captured = read_captured(&mut demo_reader);
    assert!(
        both,
        "the tap never saw both directions within the budget, so no zenohd \
         handshake reached it. wz-ap-demo said:\n{demo_captured}"
    );

    let segments = recording.lock().expect("recording lock").clone();

    // ── ANTI-VACUITY FIRST ────────────────────────────────────────────────
    assert!(
        !segments.is_empty(),
        "the tap recorded NOTHING -- an empty capture satisfies every parse \
         assertion below. wz-ap-demo said:\n{demo_captured}"
    );
    let from_wz: usize = segments
        .iter()
        .filter(|(s, _)| *s == Side::FromDialer)
        .map(|(_, b)| b.len())
        .sum();
    let from_zenohd: usize = segments
        .iter()
        .filter(|(s, _)| *s == Side::FromListener)
        .map(|(_, b)| b.len())
        .sum();
    assert!(
        from_wz > 0 && from_zenohd > 0,
        "a one-way recording is not a session: {from_wz} byte(s) from wz, \
         {from_zenohd} from zenohd"
    );

    let pcap = synthesise_pcap(&segments, 40_000, 7447);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(
        flows.len(),
        1,
        "one relayed connection is one flow; got {}",
        flows.len()
    );
    let flow = &flows[0];

    // ── THE LOAD-BEARING ASSERTION ────────────────────────────────────────
    let mut parsed: Vec<(Direction, &'static str)> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for frame in flow.frames.iter() {
        match &frame.frame {
            Ok(f) => parsed.push((frame.direction, frame_name(f))),
            Err(e) => failures.push(format!(
                "{:?} at stream_offset {}: {e:?}",
                frame.direction, frame.stream_offset
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "the analyzer FAILED to parse {} message(s) that a real zenohd session \
         put on the wire -- a finding about wz's decoder, not about the \
         fixture:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );

    let a_side = parsed.iter().filter(|(d, _)| *d == Direction::A).count();
    let b_side = parsed.iter().filter(|(d, _)| *d == Direction::B).count();
    assert!(
        a_side > 0 && b_side > 0,
        "both halves must be read: A={a_side} B={b_side}, parsed {parsed:?}"
    );

    // The handshake is what both implementations must agree on before anything
    // else can be true, so it is named rather than left to a total.
    for direction in [Direction::A, Direction::B] {
        for expected in ["Init", "Open"] {
            assert!(
                parsed
                    .iter()
                    .any(|(d, n)| *d == direction && *n == expected),
                "no {expected} parsed on {direction:?}; the session cannot have \
                 completed without one on each half. Parsed: {parsed:?}. \
                 wz-ap-demo said:\n{demo_captured}"
            );
        }
    }

    // WHAT THE ROUTER SENT, printed rather than asserted. This is the message set
    // no witness in this tree had ever seen, and pinning it on the first run
    // would freeze whatever this particular zenohd build happened to emit --
    // a golden-fixture reflex the dissect census already refuses elsewhere.
    let router_side: Vec<&str> = parsed
        .iter()
        .filter(|(d, _)| *d == Direction::B)
        .map(|(_, n)| *n)
        .collect();
    eprintln!("zenohd -> wz message set (dissected): {router_side:?}");
    eprintln!("wz -> zenohd message set (dissected): {:?}", {
        let v: Vec<&str> = parsed
            .iter()
            .filter(|(d, _)| *d == Direction::A)
            .map(|(_, n)| *n)
            .collect();
        v
    });
}

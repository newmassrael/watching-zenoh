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
//! ## What the runs found, and the correction R311y761 had to make
//!
//! R311y760 reported `zenohd -> wz = [Init, Open, Frame, Frame, Frame]` and
//! called those three Frames "what a router chose to send". THEY WERE wz's.
//! `Direction::A` is the half whose segments arrive `from_low`, and `low` is the
//! lesser endpoint by `(addr, port)` — with both addresses 127.0.0.1 that is
//! decided entirely by the two port numbers this test synthesises, and the
//! labels were written down instead of derived. Measured with the mapping
//! computed from the flow key:
//!
//! * `zenohd -> wz` = `[Init, Open]`
//! * `wz -> zenohd` = `[Init, Open, Frame, Frame, Frame]`
//!
//! So the standing result is narrower than R311y760 claimed and one carry it
//! opened was false. What IS established: bytes a stock zenohd wrote reach the
//! dissector and every message parses. What is NOT: any router-originated
//! message beyond the handshake — this wz declares no subscription, so zenohd
//! has nothing to declare back, and `[Init, Open]` is the whole of what it sent.
//!
//! The publish, meanwhile, was on the wire the entire time. `debt-carry-N66`
//! ("wz's --publish does not appear as a Frame") was an artefact of the swapped
//! label, and the assertion at the end of this test now pins it so the claim
//! cannot rest on a printed line nobody re-reads.
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

/// The synthesised endpoint ports. They are NOT the real ones (the real dialer
/// port is ephemeral and the proxy sits between), and they are named here
/// because they decide which half `Direction::A` names -- `FlowKey` orders its
/// endpoints by `(addr, port)` and both addresses are 127.0.0.1.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

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

    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
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

    // ── WHICH HALF IS WHICH, DERIVED RATHER THAN ASSUMED ──────────────────
    // `Direction::A` is the half whose segments come `from_low`, and `low` is
    // the lesser endpoint by `(addr, port)` (`FlowKey`, link.rs:144-148). Both
    // endpoints here are 127.0.0.1, so the ORDER IS DECIDED BY THE PORT NUMBERS
    // this test picked for the synthesised envelope -- which means a reader who
    // assumes "A is the dialer" is right or wrong depending on two constants
    // chosen for unrelated reasons.
    //
    // R311y761: the first version of this test assumed exactly that and printed
    // both message sets under SWAPPED labels, and the round entry that followed
    // reported wz's own Frames as the router's. So the mapping is now COMPUTED
    // from the key and asserted, rather than written down.
    let low_port = flow.flow.low.port;
    let high_port = flow.flow.high.port;
    assert_eq!(
        (low_port, high_port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "the synthesised ports decide which half is Direction::A, so this test \
         pins them: zenohd (the listener) is the LOW endpoint here"
    );
    // zenohd is the listener and the listener is `low`, so A is zenohd -> wz.
    let (zenohd_side, wz_side) = (Direction::A, Direction::B);
    let named = |want: Direction| -> Vec<&str> {
        parsed
            .iter()
            .filter(|(d, _)| *d == want)
            .map(|(_, n)| *n)
            .collect()
    };
    eprintln!(
        "zenohd -> wz message set (dissected): {:?}",
        named(zenohd_side)
    );
    eprintln!("wz -> zenohd message set (dissected): {:?}", named(wz_side));

    // THE PUBLISH REACHED THE WIRE, and this is the assertion that says so.
    // R311y760 recorded "wz's --publish does not appear as a Frame" as carry
    // N66; it was there all along, under the other label. Asserting it here is
    // what stops the claim from depending on a printed line nobody re-reads.
    assert!(
        named(wz_side).iter().any(|n| *n == "Frame"),
        "wz ran with --publish and no Frame was dissected on its half: {:?}",
        named(wz_side)
    );
}

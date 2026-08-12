// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y759 — the analyzer, pointed at bytes wz did NOT author.
//!
//! ## The gap this closes, measured rather than argued
//!
//! The analyzer's witness surface is large and it was, until this file, entirely
//! self-referential. Measured at R311y759: 649 passing tests across `wz-analyze`,
//! `wz-capture`, `wz-tls-record` and `wz-replay`; ZERO `.pcap` files anywhere in
//! the tree; ZERO `include_bytes!` of a real capture; and no lane pointing a real
//! `zenohd` or zenoh-pico at the dissector. Layers Z and E DO drive foreign
//! processes, and not one byte of what those processes emit reaches `wz-capture`.
//!
//! Every one of those 649 witnesses therefore grades the dissector against bytes
//! `wz` synthesised from its own understanding of the wire. That is not a weak
//! test — it is a test of the wrong thing: a misreading in wz's encoder is
//! reproduced exactly by wz's decoder, and the whole suite stays green while the
//! analyzer misreads real traffic in the same direction. The workspace's own rule
//! says so ("the oracle anchor is stock zenoh/pico traffic, not wz"), and nothing
//! enforced it.
//!
//! ## Why a TAP PROXY rather than a capture hook
//!
//! The bytes are taken by relaying the connection through an in-test TCP proxy:
//! the real `z_put` dials the proxy, the proxy dials `wz-ap-demo --listen`, and
//! each direction is recorded as it is forwarded. No production code changes —
//! nothing in `wz-runtime-tokio` learns about capture, so this witness cannot be
//! satisfied by a hook that only exists for it. It also needs no `CAP_NET_RAW`,
//! which is what keeps `live_capture`'s AF_PACKET tap `#[ignore]`d and unrunnable
//! in CI.
//!
//! ## What is stock here and what is synthesised — stated, not implied
//!
//! STOCK: every byte of zenoh above TCP, in both directions. The client half is
//! written by a real `libzenohpico` process; the server half is wz's, which is
//! the half being graded, and it is graded by a decoder that never saw the
//! encoder's intent.
//!
//! SYNTHESISED: the Ethernet / IPv4 / TCP envelope, because a userspace relay
//! cannot observe headers the kernel wrote. This is deliberately the part that
//! does NOT matter for this witness: decapsulation and reassembly already have
//! their own coverage over seven link types, and re-proving them is not the
//! point. What has never been tested is the layer above — that wz's transport
//! decoder consumes a foreign encoder's output — and the envelope is only the
//! vehicle that carries those bytes to it.
//!
//! ## The assertion that matters
//!
//! Not "a flow appeared". A flow appears for any two hosts exchanging anything.
//! The load-bearing assertion is that EVERY transport message parses: the run is
//! rejected if any frame in either direction comes back `Err`, and the count of
//! successfully parsed messages must be non-trivial in BOTH directions. An
//! unparsed byte here is a real finding about the analyzer, which is exactly what
//! a self-authored fixture can never produce.
//!
//! ## What the falsification established, and what it did NOT
//!
//! Measured at R311y759 by damaging the recording before synthesis, each probe
//! removed afterwards:
//!
//! * EMPTY recording -> reds on the flow count (`got 0`), so a capture that
//!   silently records nothing cannot pass as a clean run.
//! * A byte flipped near the START of the first pico segment -> reds with
//!   `A=3 B=0`: the damage desynchronises that direction's assembler and the
//!   half DISAPPEARS rather than arriving as errors. The both-halves assertion
//!   is what catches it.
//! * A byte flipped at the END of the last pico segment -> PASSES, correctly:
//!   that lands in a payload, and a payload's contents are not the transport
//!   decoder's business.
//!
//! So the `Err`-rejecting assertion is NOT yet shown to be reachable — neither
//! probe produced a single `Err` frame; damage either vanished a direction or
//! changed nothing. It is kept because it is the statement this witness exists
//! to make, and stated as unproven rather than described as if it had fired.
//! The assertions that DID carry the falsification are the flow count and the
//! both-halves count.

use std::process::Command;
use std::time::Duration;

use wz_capture::Dissection;
use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, wait_for_substring,
    wz_ap_demo_binary, zenoh_pico_cli_binary,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Side};
use wz_session_core::inbound::InboundFrame;
use wz_session_core::passive::Direction;

/// The synthesised endpoint ports. NOT the real ones (the dialer's is ephemeral
/// and the proxy sits between). They are named because they decide which half
/// `Direction::A` is: `FlowKey` orders endpoints by `(addr, port)` and both
/// addresses are 127.0.0.1, so the lower port is `low` and `low` is `A`.
/// R311y761 found the sibling zenohd witness reporting its two halves under
/// SWAPPED labels for exactly this reason.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// A short name for a parsed transport message, for the assertion messages.
fn frame_name(frame: &InboundFrame) -> &'static str {
    match frame {
        InboundFrame::Init { .. } => "Init",
        InboundFrame::Open { .. } => "Open",
        InboundFrame::Close { .. } => "Close",
        InboundFrame::KeepAlive { .. } => "KeepAlive",
        InboundFrame::Frame { .. } => "Frame",
        InboundFrame::Fragment { .. } => "Fragment",
        InboundFrame::Join { .. } => "Join",
        // EXHAUSTIVE on purpose (no `_ =>`): a new transport message added to
        // the enum must be named here, because this witness reports what a
        // foreign encoder actually emitted and a catch-all would quietly file a
        // brand-new message type as "something".
        InboundFrame::Unknown { .. } => "Unknown",
    }
}

/// THE WITNESS: a real zenoh-pico session, relayed and dissected.
// wz-proves: session-unicast-accept pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer Ewire runs via --ignored"]
fn the_analyzer_parses_every_message_a_real_zenoh_pico_session_puts_on_the_wire() {
    let demo = wz_ap_demo_binary();
    let z_put = zenoh_pico_cli_binary("z_put");

    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let (mut demo_guard, mut demo_reader, wz_port) = spawn_on_ephemeral_port(
        &demo,
        &["--listen", "127.0.0.1:0", "--key", "demo/**"],
        "listening on 127.0.0.1:",
        "wz-ap-demo (--listen, behind the tap proxy)",
        demo_stderr,
    );

    let (proxy_port, recording) = tap_proxy(wz_port);

    let mut capture = tempfile::tempfile().expect("zenoh-pico z_put capture");
    let put = Command::new(&z_put)
        .args([
            "-e",
            &format!("tcp/127.0.0.1:{proxy_port}"),
            "-k",
            "demo/tapped",
            "-v",
            "hello-through-the-tap",
        ])
        .stdout(capture.try_clone().expect("clone capture"))
        .stderr(capture.try_clone().expect("clone capture"))
        .status()
        .expect("spawn zenoh-pico z_put");
    assert!(
        put.success(),
        "the real zenoh-pico z_put exited {put:?} against the tapped acceptor -- \
         no session means no stock bytes to dissect. Its output was:\n{}",
        read_captured(&mut capture)
    );

    let fired = "SUBSCRIBER FIRED";
    let delivered = wait_for_substring(&mut demo_reader, fired, Duration::from_secs(10));
    delivered.expect(
        "wz-ap-demo never delivered the relayed sample, so the recording below \
         would be a partial handshake rather than a session",
    );
    graceful_terminate(demo_guard.child_mut(), Duration::from_secs(5));

    // Give the relay threads their EOF before reading the log.
    std::thread::sleep(Duration::from_millis(200));
    let segments = recording.lock().expect("recording lock").clone();

    // ── ANTI-VACUITY FIRST ────────────────────────────────────────────────
    // Every assertion below is satisfied by an empty capture, so the floor
    // comes before the comparisons rather than after them.
    assert!(
        !segments.is_empty(),
        "the tap recorded NOTHING -- the proxy was bypassed or never accepted, \
         and an empty capture would satisfy every parse assertion below"
    );
    let from_pico: usize = segments
        .iter()
        .filter(|(s, _)| *s == Side::FromDialer)
        .map(|(_, b)| b.len())
        .sum();
    let from_wz: usize = segments
        .iter()
        .filter(|(s, _)| *s == Side::FromListener)
        .map(|(_, b)| b.len())
        .sum();
    assert!(
        from_pico > 0 && from_wz > 0,
        "a one-way recording is not a session: {from_pico} byte(s) from pico, \
         {from_wz} from wz"
    );

    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(
        flows.len(),
        1,
        "one relayed connection is one flow; got {} -- a different count means \
         the synthesised envelope split the stream",
        flows.len()
    );
    let flow = &flows[0];

    // ── THE LOAD-BEARING ASSERTION ────────────────────────────────────────
    // Every transport message a foreign encoder produced must parse. This is
    // the statement no self-authored fixture can make.
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
        "the analyzer FAILED to parse {} message(s) that a real zenoh-pico \
         session put on the wire -- this is a finding about wz's decoder, not \
         about the fixture:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );

    // WHICH HALF IS WHICH, DERIVED rather than assumed (R311y761). wz is the
    // LISTENER here and pico dials, so wz holds the lower synthesised port and
    // is `Direction::A`. The port order the mapping rests on is asserted, not
    // written down -- the sibling zenohd witness reported its halves swapped
    // because it stated the mapping instead of computing it.
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "the synthesised ports decide which half is Direction::A"
    );
    let (wz_side, pico_side) = (Direction::A, Direction::B);
    let named = |want: Direction| -> Vec<&str> {
        parsed
            .iter()
            .filter(|(d, _)| *d == want)
            .map(|(_, n)| *n)
            .collect()
    };
    assert!(
        !named(wz_side).is_empty() && !named(pico_side).is_empty(),
        "both halves must be read: wz={:?} pico={:?}",
        named(wz_side),
        named(pico_side)
    );
    // The z_put's sample is PICO's, so it must land on pico's half. Asserting
    // the side and not merely the presence is what the zenohd correction taught:
    // a Frame on the wrong half would have read as success.
    assert!(
        named(pico_side).iter().any(|n| *n == "Frame"),
        "the real z_put's sample did not arrive on pico's half: {:?}",
        named(pico_side)
    );
    eprintln!("pico -> wz message set (dissected): {:?}", named(pico_side));
    eprintln!("wz -> pico message set (dissected): {:?}", named(wz_side));

    // The handshake is the part pico authored most independently, so name it
    // rather than resting on a total. Both directions carry an Init and an Open.
    for direction in [Direction::A, Direction::B] {
        for expected in ["Init", "Open"] {
            assert!(
                parsed
                    .iter()
                    .any(|(d, n)| *d == direction && *n == expected),
                "no {expected} parsed on {direction:?}; the session cannot have \
                 completed without one on each half. Parsed: {parsed:?}"
            );
        }
    }
}

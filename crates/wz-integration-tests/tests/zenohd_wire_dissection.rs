// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! ## R311y764 — and what was INSIDE the router's Frames
//!
//! R311y762 gave the router something to route and measured `zenohd -> wz =
//! [Init, Open, Frame, Frame]`. It counted those Frames; it never opened them,
//! and carry N68 said so. A `Frame` is a container, so that census is identical
//! whether the two carried the routed publication or two records this decoder
//! cannot name — the transport layer was graded against a real router and the
//! RECORD layer had never been graded against one at all.
//!
//! Both legs now decode the batch inside every Frame on zenohd's half, and the
//! two readings are each other's control at that layer too:
//!
//! * idle leg — `[]`. A stock zenohd sends an idle face no records.
//! * routing leg — `["Push", "Push"]`. The publisher's bytes never touched this
//!   tap, so a Push here is the sample re-encoded by the router onto this face.
//!
//! ## Falsification
//!
//! Bypassing the tap (dialling zenohd directly) reds with `the tap never saw
//! both directions`, so "the relay is on the path" is measured rather than
//! assumed — the session succeeds either way, and only the recording tells them
//! apart. The shared harness's other probes (empty recording, damaged segment)
//! were measured in the pico witness against the same code.
//!
//! For the record-layer half (R311y764): asking the routing leg for a `Declare`
//! instead of a `Push` reds with `["Push", "Push"]` in the message, so the
//! assertion reads what the batch actually holds rather than passing on any
//! non-empty list. The idle leg's `[]` is the other half of that binding — a
//! `records_on` that returned junk would red there.
//!
//! And the `Err`-rejecting assertion is shown REACHABLE on these bytes rather
//! than assumed to be (carry N64, which was filed against the pico witness and
//! is the same question here about a different encoder). Every byte of zenohd's
//! half is flipped in turn: on a representative run over its 68 bytes, 6
//! positions reach the `Err` arm, 3 vanish the direction, 59 change nothing.
//! Existence is asserted, never an offset — the counts move with the
//! handshake's length.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_capture::Dissection;
use wz_integration_tests::common::{
    read_captured, wait_for_substring, wait_for_tcp_accept_alive, wz_ap_demo_binary, zenohd_binary,
    ChildGuard, PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_integration_tests::wire_tap::{
    sweep_single_byte_damage, synthesise_pcap, tap_proxy, Recording, Side,
};
use wz_session_core::inbound::InboundFrame;
// R2277 (open-debt item 613) — `NetworkMessage` is no longer named here. It was
// imported for a `record_name` helper whose eight `match` arms each spelled a
// message name, which is the defect item 613 filed: `dissect_batch` supplies the
// words now, and the decoder is used only for its COUNT, as the dissector's
// independent second opinion.
use wz_session_core::network_message::parse_frame_payload;
use wz_session_core::passive::Direction;

/// The synthesised endpoint ports. They are NOT the real ones (the real dialer
/// port is ephemeral and the proxy sits between), and they are named here
/// because they decide which half `Direction::A` names -- `FlowKey` orders its
/// endpoints by `(addr, port)` and both addresses are 127.0.0.1.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// A short name for a parsed transport message.
///
/// Still EXHAUSTIVE (no `_ =>`) — this witness reports what a foreign encoder
/// actually emitted, and a catch-all would file a brand-new message type as
/// "something" — but exhaustive ONCE, in [`InboundFrame::kind_name`], whose
/// arms sit beside the variants under the same `#[cfg]`s. The copy that used
/// to live here was a second list to keep in step, and it fell behind.
fn frame_name(frame: &InboundFrame) -> &'static str {
    frame.kind_name()
}

/// The vocabulary every name this witness reports has to belong to.
///
/// R2277 (open-debt item 613). `wz-capture`'s `MESSAGE_R5` is the declared
/// `fields.message` family — fourteen words, no `#[cfg]` on the constant — and
/// it is the ONE population this file may be held to. The three other candidate
/// sets were measured and refused: `InboundFrame::kind_name` has nine arms of
/// which seven are `#[cfg]`-gated, so a grep sees more than rustc does (R2272's
/// lesson exactly); `ScoutingFrame::kind_name` names three messages that travel
/// on a MID space this TCP tap never carries; and this file's own literals were
/// the defect. It is also the constant the CONSUMER's linter pins, so the day it
/// moves both sides go red together.
const VOCABULARY: &[&str] = wz_capture::doc_revision::MESSAGE_R5;

/// What each leg's names ARE, per leg, measured — and asserted as EQUALITY.
///
/// Item 613's done-when ③: a name the genuine article never sends must not be
/// asserted, or the witness is red forever. So the pin is per leg and it is
/// exact in BOTH directions. A name appearing that this leg never carried is a
/// new observation; a name in the pin that stops appearing is a leg that lost
/// coverage — and a one-directional `⊆` would have let the second through,
/// which is how a pin turns into decoration.
///
/// MEASURED at R2277 on this harness, with `--nocapture`, over both halves of
/// each flow:
///
/// * idle     — transport `[Init, Open, Frame]`, no records on either half.
/// * routing  — the same transport set, plus `Push` inside zenohd's Frames.
/// * interest — the same transport set, plus `Declare`, which is wz's: the
///   subscriber declaration it sends. zenohd's half of that leg carries no
///   record at all, which is why the `Interest` row below says so.
const IDLE_LEG_NAMES: &[&str] = &["Frame", "Init", "Open"];
/// See [`IDLE_LEG_NAMES`]. `Push` is the routed sample, re-encoded by zenohd.
const ROUTING_LEG_NAMES: &[&str] = &["Frame", "Init", "Open", "Push"];
/// See [`IDLE_LEG_NAMES`]. `Declare` is wz's subscriber declaration.
const INTEREST_LEG_NAMES: &[&str] = &["Declare", "Frame", "Init", "Open"];

/// The other half of the partition: a declared word this tap does NOT carry,
/// each with the reason it cannot.
///
/// Item 613's done-when ③ asked for the absent names to be "written down as a
/// fact rather than inferred", and a comment would not be measured. This is a
/// TABLE the test compares against the vocabulary, so a message that becomes
/// observable reds here — in the one place that records why it used to be
/// absent — instead of silently widening a per-leg pin.
const NOT_CARRIED_HERE: &[(&str, &str)] = &[
    (
        "Close",
        "sent at teardown; these legs kill the child instead",
    ),
    (
        "Fragment",
        "needs a message larger than one batch, which nothing here sends",
    ),
    (
        "Interest",
        "neither half sends one: wz declares its subscriber with a Declare, and \
         zenohd's half of that leg carries no record at all (measured)",
    ),
    ("Join", "a MULTICAST announcement; this tap is TCP unicast"),
    (
        "KeepAlive",
        "sent on an idle lease; every leg here finishes inside one",
    ),
    (
        "Oam",
        "a control-plane envelope neither side has a reason to send on these legs",
    ),
    ("Request", "no leg issues a query"),
    ("Response", "no leg issues a query, so nothing replies"),
    (
        "ResponseFinal",
        "no leg issues a query, so nothing closes one",
    ),
];

/// Every record name in a `Frame` payload, taken from the DISSECTOR.
///
/// R2277 (open-debt item 613) — this used to be a `record_name` helper whose
/// eight `match` arms each spelled their own literal, and item 613 is what that
/// cost: a name in a `match` arm says the word OCCURS, never that it is the
/// right word. MEASURED before the fix, as a command: renaming the `Declare`
/// arm to `Xeclare` left all three witnesses GREEN, because this tap carries no
/// Declare and nothing else read that arm. Only `Push` was load-bearing, held
/// by one `any(|r| r == "Push")` below.
///
/// So the literals are gone rather than asserted. `dissect_batch` names each
/// record through `MessageName`, which
/// `the_message_vocabulary_is_the_one_the_dispatchers_produce` already holds to
/// the dispatchers over all thirty-two MID values, and `MessageName::names` is
/// the population `MESSAGE_R5` is declared from. A word this witness prints is
/// now the library's, and there is no arm here left to move.
fn dissected_record_names(payload: &[u8]) -> (Vec<String>, Option<String>) {
    let batch = wz_session_core::dissect::dissect_batch(payload, 0);
    let names = batch
        .records
        .iter()
        .map(|f| f.name.to_string())
        .collect::<Vec<_>>();
    let halt = batch
        .halt
        .as_ref()
        .map(|h| format!("{h:?} ({} byte(s) unparsed)", batch.unparsed_bytes));
    (names, halt)
}

/// Decode the record batch inside every `Frame` a chosen half sent.
///
/// R311y764 (carry N68). Both witnesses in this file used to stop at the
/// transport envelope: they counted `Frame` and asserted its presence, which
/// establishes that a router spoke and nothing at all about WHAT it said. A
/// `Frame` is a container, and `[Init, Open, Frame, Frame]` is the same census
/// whether the two carried the routed publication or two records wz cannot
/// decode.
///
/// Returns the record names in wire order plus the batches that FAILED to
/// decode, kept separate on purpose: an empty name list and an empty failure
/// list mean "the router sent no records", while a non-empty failure list is a
/// defect report against `parse_frame_payload`. Collapsing them would let the
/// second read as the first.
///
/// R2277 (open-debt item 613) — TWO INDEPENDENT READINGS of the same payload,
/// and their disagreement is a third finding. `parse_frame_payload` is the
/// CODEC decoder (it builds `NetworkMessage` values) and `dissect_batch` is the
/// DISSECTOR walk (it names records from the MID); they are separate tables, so
/// a payload one of them reads as two records and the other as one is a defect
/// in whichever is wrong, and neither could report it alone. The names come from
/// the dissector because that is the word a consumer is actually handed.
fn records_on(
    flow: &wz_capture::FlowDissection,
    side: Direction,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut names = Vec::new();
    let mut failures = Vec::new();
    let mut disagreements = Vec::new();
    for frame in flow.frames.iter() {
        if frame.direction != side {
            continue;
        }
        let Ok(InboundFrame::Frame { payload, .. }) = &frame.frame else {
            continue;
        };
        let decoded = match parse_frame_payload(payload) {
            Ok(records) => records,
            Err(e) => {
                failures.push(format!(
                    "stream_offset {} ({} payload byte(s)): {e:?}",
                    frame.stream_offset,
                    payload.len()
                ));
                continue;
            }
        };
        let (walked, halt) = dissected_record_names(payload);
        if let Some(halt) = halt {
            disagreements.push(format!(
                "stream_offset {}: the codec decoded {} record(s) but the \
                 dissector HALTED: {halt}",
                frame.stream_offset,
                decoded.len()
            ));
        } else if walked.len() != decoded.len() {
            disagreements.push(format!(
                "stream_offset {}: the codec decoded {} record(s), the dissector \
                 walked {} ({walked:?})",
                frame.stream_offset,
                decoded.len(),
                walked.len()
            ));
        }
        names.extend(walked);
    }
    (names, failures, disagreements)
}

/// Every name this witness reports must be a word [`VOCABULARY`] declares.
///
/// Item 613's done-when ①, and the reason it is a function rather than a line in
/// each leg: three legs report names and the rule is ONE fact. An `Unknown`
/// transport kind or a record MID the dissector cannot name reaches here as a
/// word the vocabulary does not carry, which is exactly the finding — a message
/// the genuine article sent and this build cannot name.
fn assert_named_by_the_vocabulary(observed: &[&str], pinned: &[&str], what: &str) {
    let stranger: Vec<&&str> = observed
        .iter()
        .filter(|n| !VOCABULARY.contains(n))
        .collect();
    assert!(
        stranger.is_empty(),
        "{what}: {stranger:?} is not a word `MESSAGE_R5` declares, so a consumer \
         handed this listing would receive a message name with no vocabulary \
         behind it. Observed: {observed:?}; vocabulary: {VOCABULARY:?}"
    );
    // EQUALITY OF SETS, both directions. A `⊆` would pass a pin that has gone
    // wider than the wire, which is the shape that makes a pin decoration.
    let mut seen: Vec<&str> = observed.to_vec();
    seen.sort_unstable();
    seen.dedup();
    let mut want: Vec<&str> = pinned.to_vec();
    want.sort_unstable();
    assert_eq!(
        seen, want,
        "{what}: the set of message names this leg put on the wire moved. \
         Extra names are a NEW observation (widen the pin, and say what \
         produced them); missing ones are coverage this leg used to have and \
         no longer does. Observed in wire order: {observed:?}"
    );
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
        named(wz_side).contains(&"Frame"),
        "wz ran with --publish and no Frame was dissected on its half: {:?}",
        named(wz_side)
    );

    // ── THE RECORD-LAYER CONTROL (R311y764, carry N68) ────────────────────
    // The second witness asserts that a routing zenohd's Frames carry a `Push`.
    // That assertion is only worth something if THIS leg — same harness, same
    // router build, one difference: nothing to route — produces no such record.
    // Asserted rather than left implied: if a stock zenohd emitted records to
    // an idle face, the second leg's Push would not be evidence of routing.
    let (idle_records, idle_failures, idle_disagreements) = records_on(flow, zenohd_side);
    eprintln!("zenohd -> wz (idle) RECORD set: {idle_records:?}");
    assert!(
        idle_failures.is_empty(),
        "the idle router's Frames failed to decode: {idle_failures:?}"
    );
    assert!(
        idle_disagreements.is_empty(),
        "the codec decoder and the dissector disagree about the idle router's \
         batches: {idle_disagreements:?}"
    );
    assert!(
        idle_records.is_empty(),
        "an IDLE zenohd sent record(s) to a face that declares nothing: \
         {idle_records:?}. The routing witness reads a `Push` here as proof of \
         routing, and that reading depends on this half being silent"
    );

    // R2277 (open-debt item 613) — AND EVERY NAME THIS LEG REPORTED IS A WORD
    // THE VOCABULARY DECLARES. Both halves, because a name is a name whichever
    // encoder wrote it, and `Unknown` on either would arrive here as a stranger.
    let mut said: Vec<&str> = named(zenohd_side);
    said.extend(named(wz_side));
    said.extend(idle_records.iter().map(String::as_str));
    assert_named_by_the_vocabulary(&said, IDLE_LEG_NAMES, "the idle leg's names");

    // ── AND IS THE Err ARM REACHABLE ON THESE BYTES? (R311y764, N64) ──────
    // The same question the pico witness asks, asked separately because the
    // answer is about an ENCODER and these are a different encoder's bytes. The
    // half to damage is zenohd's: damaging wz's own would ask whether wz's
    // decoder objects to wz's encoder, which is the self-witness this harness
    // exists to escape. zenohd LISTENS here (pico dialled in the sibling), so
    // the foreign half is `FromListener` — the roles swap between the two
    // witnesses and the constant has to swap with them.
    let sweep = sweep_single_byte_damage(&segments, Side::FromListener, DIALER_PORT, LISTENER_PORT);
    eprintln!("damage sweep over zenohd's half: {sweep:?}");
    assert!(
        sweep.swept > 0,
        "the damage sweep visited no byte, so its verdict is about nothing"
    );
    assert!(
        sweep.yielded_err > 0,
        "NO single-byte damage to the bytes a real zenohd wrote reaches the \
         `Err` arm: {sweep:?}. The parse assertion above rejects any frame that \
         comes back Err, and this would say it is unfireable on this encoder's \
         output — a finding about wz's decoder, not a reason to drop it"
    );
    // R2053 (open-debt item 371) — the CLASSIFIER's own invariant, which this
    // consumer never asserted while the three no-frame outcomes were fused into
    // one counter. Every visited position must land in exactly one bucket; an
    // arm that stops counting makes the totals disagree, and nothing here would
    // have noticed. Cheap, capture-independent, and it holds on any recording.
    //
    // The per-bucket SPLIT is pinned in `wire_tap`'s own tests against a crafted
    // handshake, deliberately not here: this leg's capture is a live zenohd's,
    // so its byte count varies run to run and exact literals would be noise.
    // Item 371's second half was that the classification sat behind THIS
    // `#[ignore]`d lane; it does not any more.
    assert!(
        sweep.is_exhaustive(),
        "the damage sweep's buckets do not account for every swept position, so \
         one arm is not counting: {sweep:?}"
    );
    assert_eq!(
        sweep.pcap_rejected, 0,
        "a damaged recording produced a pcap the reader REFUSED: {sweep:?}. \
         That cannot happen by construction -- the damage is applied to the \
         recording and `synthesise_pcap` then computes the checksums over the \
         damaged bytes -- so a non-zero here means the synthesiser stopped \
         doing that, which would make every outcome below it a statement about \
         a corrupt envelope rather than about wz's decoder"
    );
}

/// THE SECOND WITNESS (R311y762, carry N67): a router with something to route.
///
/// ## Why the first witness could not produce this
///
/// R311y760 believed Layer Ewirez had dissected router-originated messages;
/// R311y761 measured that it had not, and that zenohd's whole contribution was
/// `[Init, Open]`. The reason is not a gap in the tap — it is that the wz side
/// of that capture DECLARES NOTHING, so a router has nothing to tell it. A
/// handshake is what an acceptor owes any peer; it says nothing about the
/// messages that make a router a router.
///
/// So this one gives it a reason. A wz SUBSCRIBER dials through the tap, and a
/// SECOND wz process publishes to the same keyexpr straight at zenohd, bypassing
/// the tap entirely. Nothing the publisher writes is recorded — what the tap sees
/// on zenohd's half is what ZENOHD decided to send, having matched a subscription
/// against a publication and routed between two faces.
///
/// ## Two wz processes rather than a pico client
///
/// The publisher could have been a real `z_put`, and that would add zenoh-pico to
/// this lane's prerequisites for a leg whose foreign half is zenohd's either way.
/// The publisher here is scaffolding that gives the router work; the bytes under
/// test are the router's, and they are equally foreign whoever caused them.
// wz-proves: routing-router zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (two wz-ap-demo + zenohd); Layer Ewirez runs via --ignored"]
fn the_analyzer_parses_what_a_real_zenohd_sends_when_it_actually_routes() {
    let demo = wz_ap_demo_binary();
    let reservation = PortReservation::pick();
    let zenohd_port = reservation.port();

    let mut zenohd = ChildGuard::wrap(
        "zenohd (routing between two wz faces)",
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

    // THE OBSERVED FACE: a subscriber, through the tap.
    let sub_stderr = tempfile::tempfile().expect("tempfile for subscriber stderr");
    let sub_writer = sub_stderr.try_clone().expect("dup subscriber stderr");
    let mut sub_reader = sub_stderr;
    let mut subscriber = ChildGuard::wrap(
        "wz-ap-demo subscriber (through the tap proxy)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{proxy_port}"))
            .arg("--key")
            .arg("demo/**")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(sub_writer))
            .spawn()
            .expect("spawn wz-ap-demo subscriber"),
    );
    assert!(
        wait_for_both_directions(&recording, Duration::from_secs(15)),
        "the subscriber never completed a handshake through the tap"
    );

    // THE UNOBSERVED FACE: a publisher, straight at zenohd. Its bytes are NOT in
    // the recording, which is the point -- anything that reaches the tap because
    // of it was written by the router.
    // Its stderr is CAPTURED, not discarded. The first attempt at this witness
    // threw it away and the failure ("no routed sample") could not be told apart
    // from a publisher that never started -- this repo's own guard rule F2, in
    // the test that needed it.
    let pub_stderr = tempfile::tempfile().expect("tempfile for publisher stderr");
    let pub_writer = pub_stderr.try_clone().expect("dup publisher stderr");
    let mut pub_reader = pub_stderr;
    let mut publisher = ChildGuard::wrap(
        "wz-ap-demo publisher (direct to zenohd, off the tap)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{zenohd_port}"))
            // A DISTINCT zid, without which this does not work at all: the demo
            // carries a HARDCODED zid (`runner.rs:1478-1481` says so in as many
            // words), so a second instance against the same router is refused
            // with `session open failed: Terminal`. That was this witness's
            // first failure, and it was only diagnosable because the publisher's
            // stderr is captured.
            .arg("--zid")
            .arg("beefcafe00000002")
            .arg("--publish")
            .arg("demo/routed")
            .arg("--value")
            .arg("routed-by-a-real-zenohd")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(pub_writer))
            .spawn()
            .expect("spawn wz-ap-demo publisher"),
    );

    let fired = wait_for_substring(&mut sub_reader, "SUBSCRIBER FIRED", Duration::from_secs(20));
    std::thread::sleep(Duration::from_millis(300));
    let _ = publisher.child_mut().kill();
    let _ = publisher.child_mut().wait();
    let _ = subscriber.child_mut().kill();
    let _ = subscriber.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    std::thread::sleep(Duration::from_millis(200));

    let sub_captured = read_captured(&mut sub_reader);
    let pub_captured = read_captured(&mut pub_reader);
    fired.unwrap_or_else(|_| {
        panic!(
            "the subscriber never received the routed sample, so zenohd never \
             routed and this capture would hold only a handshake.\n\
             --- subscriber ---\n{sub_captured}\n--- publisher ---\n{pub_captured}"
        )
    });

    let segments = recording.lock().expect("recording lock").clone();
    assert!(!segments.is_empty(), "the tap recorded nothing");

    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(flows.len(), 1, "one relayed connection is one flow");
    let flow = &flows[0];

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
        "the analyzer FAILED to parse {} message(s) a routing zenohd put on the \
         wire:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );

    // The mapping is DERIVED, on the rule R311y761 established: `low` is the
    // lesser endpoint and zenohd is the listener, so A is zenohd's half.
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "the synthesised ports decide which half is Direction::A"
    );
    let named = |want: Direction| -> Vec<&str> {
        parsed
            .iter()
            .filter(|(d, _)| *d == want)
            .map(|(_, n)| *n)
            .collect()
    };
    let zenohd_sent = named(Direction::A);
    eprintln!("zenohd -> wz (routing) message set: {zenohd_sent:?}");
    eprintln!(
        "wz -> zenohd (routing) message set: {:?}",
        named(Direction::B)
    );

    // THE ASSERTION N67 EXISTS FOR. A handshake is what any acceptor owes; a
    // Frame on zenohd's half is a message it chose to send, and the only thing
    // that could have caused one is the publication it matched and routed. The
    // publisher's own bytes never touched this tap.
    let handshake_only: Vec<&str> = zenohd_sent
        .iter()
        .filter(|n| **n != "Init" && **n != "Open")
        .copied()
        .collect();
    assert!(
        !handshake_only.is_empty(),
        "zenohd sent nothing beyond the handshake even though it routed a \
         sample to this face: {zenohd_sent:?}. That is the state R311y761 \
         measured, and this witness exists to leave it."
    );
    assert!(
        zenohd_sent.contains(&"Frame"),
        "no Frame on zenohd's half: {zenohd_sent:?}"
    );

    // ── AND WHAT WAS INSIDE THEM (R311y764, carry N68) ────────────────────
    // Up to here this witness has counted the router's containers. N68 was
    // filed because that is all it did: `[Init, Open, Frame, Frame]` is the
    // same census whether those Frames carried the routed publication or two
    // records the decoder cannot name. The transport layer was proven against
    // a real router; the record layer had never been graded against one at all.
    let (records, record_failures, record_disagreements) = records_on(flow, Direction::A);
    eprintln!("zenohd -> wz (routing) RECORD set: {records:?}");
    assert!(
        record_disagreements.is_empty(),
        "the codec decoder and the dissector disagree about the routing \
         router's batches: {record_disagreements:?}"
    );

    assert!(
        record_failures.is_empty(),
        "the analyzer parsed the router's Frames but FAILED to decode the \
         record batch inside {} of them -- a finding about wz's \
         parse_frame_payload, not about the fixture:\n  {}",
        record_failures.len(),
        record_failures.join("\n  ")
    );
    // ANTI-VACUITY: `record_failures` is empty for a router that sent no
    // records at all, so the empty case has to be refused separately or the
    // assertion above proves nothing.
    assert!(
        !records.is_empty(),
        "zenohd's Frames carried NO records. A Frame with an empty batch is a \
         valid transport envelope, so the parse assertions above would all pass \
         on it -- which is exactly why this witness cannot stop at them"
    );
    // THE RECORD THAT MAKES A ROUTER A ROUTER. `Push` is the pub/sub data
    // carrier: the publisher's own bytes never touched this tap, so a Push
    // arriving on zenohd's half is the routed sample, re-encoded by the router
    // onto this face. Any other record here (a Declare, an Interest) would be
    // the router talking about the session rather than routing through it.
    assert!(
        records.iter().any(|r| r == "Push"),
        "zenohd routed a sample to this face and the subscriber fired, but no \
         Push was decoded out of its Frames: {records:?}"
    );
    // A record whose MID wz does not decode is the one outcome that would be a
    // defect rather than a description, and `Unknown` is how the batch decoder
    // reports it WITHOUT failing -- so it has to be refused by name.
    let unknown: Vec<&String> = records
        .iter()
        .filter(|r| r.starts_with("Unknown"))
        .collect();
    assert!(
        unknown.is_empty(),
        "a real zenohd sent record(s) this decoder has no envelope for: \
         {unknown:?} (whole set: {records:?})"
    );

    // R2277 (open-debt item 613) — the transport names AND the record names of
    // this leg, held to the declared vocabulary. This is the leg that reaches
    // the record layer at all, so it is the one whose `Push` is checked as a
    // WORD rather than only as a presence.
    let mut said: Vec<&str> = named(Direction::A);
    said.extend(named(Direction::B));
    said.extend(records.iter().map(String::as_str));
    assert_named_by_the_vocabulary(&said, ROUTING_LEG_NAMES, "the routing leg's names");
}

/// R2277 (open-debt item 613) — WHICH WORDS THIS WITNESS CAN AND CANNOT REACH.
///
/// The two legs above assert that every name they observed is declared. This
/// asserts the other half of item 613's done-when ③: that the pinned set of
/// observable names is itself a subset of the vocabulary, and it NAMES the
/// words the vocabulary carries that this tap does not.
///
/// Written as a test rather than a comment because a sentence about which
/// messages a TCP unicast tap cannot carry is exactly the kind of claim this
/// tree keeps finding to have rotted. Nine of the fourteen are absent for a
/// structural reason (`Join` is a multicast announcement; `Fragment` needs a
/// message larger than the batch; `Close` and `KeepAlive` come at teardown and
/// idle, which these legs do not reach), and one is absent only because no leg
/// declares a subscription to zenohd — which is a gap a future leg could close
/// and this list would then have to move, loudly.
///
/// It carries no `#[ignore]`: it needs no zenohd, and the count guard on the
/// Ewirez lane reads the `--ignored` run, so this one runs under Layer C1
/// instead. Both are real lanes; neither can silently stop.
///
/// R2279 — that is now a DERIVED verdict rather than a convention it broke.
/// Layer C0 held every `#[test]` in this file to `#[ignore]` because the FILE
/// spawns zenohd; the obligation is per TEST, and this one reaches no spawning
/// helper. It witnesses no atom either: the words it partitions are wz's own
/// declared vocabulary, not anything a foreign encoder put on a wire.
// wz-proves: none -- partitions this tree's own vocabulary; reaches no foreign encoder
#[test]
fn the_names_this_witness_reports_are_the_declared_vocabulary() {
    // The carried half is DERIVED from the three per-leg pins, never written a
    // fourth time. A leg that gains a message widens this by construction, so
    // the partition below then fails against `NOT_CARRIED_HERE` and the round
    // that widened it has to say which row it took out and why.
    let mut carried: Vec<&str> = IDLE_LEG_NAMES
        .iter()
        .chain(ROUTING_LEG_NAMES.iter())
        .chain(INTEREST_LEG_NAMES.iter())
        .copied()
        .collect();
    carried.sort_unstable();
    carried.dedup();
    assert!(
        !carried.is_empty(),
        "no leg pins any name, so `assert_named_by_the_vocabulary` compares \
         against nothing and every leg would pass on an empty wire -- a \
         population of zero is not a pass here either"
    );
    let stranger: Vec<&&str> = carried.iter().filter(|n| !VOCABULARY.contains(n)).collect();
    assert!(
        stranger.is_empty(),
        "the per-leg pins name {stranger:?}, which `MESSAGE_R5` does not \
         declare. Those pins are a SUBSET of the vocabulary by construction; a \
         word outside it is a typo or a message the library no longer names"
    );
    // THE PARTITION, which is what makes the "not carried" half a measurement
    // rather than a remark. Every declared word is in exactly one of the two
    // sets; a word in neither is UNCLASSIFIED, and unclassified is not a pass.
    let mut partitioned: Vec<&str> = carried
        .iter()
        .chain(NOT_CARRIED_HERE.iter().map(|(n, _)| n))
        .copied()
        .collect();
    partitioned.sort_unstable();
    let mut declared: Vec<&str> = VOCABULARY.to_vec();
    declared.sort_unstable();
    assert_eq!(
        partitioned, declared,
        "the carried names and `NOT_CARRIED_HERE` must PARTITION `MESSAGE_R5`. \
         A word in neither is one nobody has decided about, and a word in both \
         is a claim that it is simultaneously carried and not"
    );
    eprintln!(
        "carried by this tap ({} of {}): {carried:?}",
        carried.len(),
        VOCABULARY.len()
    );
    eprintln!("declared but NOT carried:");
    for (name, why) in NOT_CARRIED_HERE {
        eprintln!("  {name}: {why}");
    }
}

/// ITEM 271 — THE INTEREST PLANE, OVER BYTES THIS WORKSPACE DID NOT WRITE.
///
/// # The item
///
/// Every fixture the interest plane has ever been driven by is built by
/// `interest_build` / `declare_build` — this tree's own encoders. That is the
/// right discipline for "does the plane read what wz SENDS", and it is not the
/// question a foreign capture asks. R311y870 filed it and named the shape of
/// the gap exactly: the interop lanes exist, and not one of them reads a
/// capture with this plane.
///
/// # What this leg claims, and what it does not
///
/// It runs `wz_capture::interest::interests` over a real zenohd session and
/// asserts that whatever the plane produced is INTERNALLY SOUND — every row
/// points at a flow this dissection holds, no withdrawal precedes its own
/// declaration, and nothing closes a declaration the tap never saw opened.
/// That is what a foreign capture can prove and a self-authored fixture
/// cannot: a fixture can only show the plane reads bytes this tree wrote in
/// the shape this tree writes them.
///
/// ⚠ The assertion is deliberately NOT "the plane found declarations". A
/// capture where the router happened to declare nothing is a description of
/// that run, not a defect; a capture where the plane invented a row IS one.
/// Writing it the other way would make this witness fail on zenohd's mood.
///
/// It does NOT claim the exotic cases item 271 lists — an `InterestOptions`
/// combination wz's builders cannot make, a reused id, a face-closing
/// `Interest(Final)`. Each needs a fixture that makes a router DO it. This is
/// the door they come through, not everything that walks it.
// wz-proves: session-unicast-open wz->zenohd
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenohd); Layer Ewirez runs via --ignored"]
fn the_interest_plane_reads_a_real_zenohd_session() {
    let demo = wz_ap_demo_binary();
    let reservation = PortReservation::pick();
    let zenohd_port = reservation.port();

    let mut zenohd = ChildGuard::wrap(
        "zenohd (interest plane witness)",
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
    if let Err(e) =
        wait_for_tcp_accept_alive(zenohd.child_mut(), zenohd_port, ZENOHD_TCP_ACCEPT_BUDGET)
    {
        panic!("zenohd never accepted: {e}");
    }

    let (proxy_port, recording) = tap_proxy(zenohd_port);

    // A SUBSCRIBER, because a subscriber is what puts a `DeclareSubscriber` on
    // the wire and gives the router something to answer.
    let sub_stderr = tempfile::tempfile().expect("tempfile for subscriber stderr");
    let sub_writer = sub_stderr.try_clone().expect("dup subscriber stderr");
    let mut sub_reader = sub_stderr;
    let mut subscriber = ChildGuard::wrap(
        "wz-ap-demo subscriber (through the tap proxy)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{proxy_port}"))
            .arg("--key")
            .arg("demo/**")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(sub_writer))
            .spawn()
            .expect("spawn wz-ap-demo subscriber"),
    );
    let handshook = wait_for_both_directions(&recording, Duration::from_secs(15));
    // A moment past the handshake, so a declaration the demo sends after its
    // session opens is inside the recording rather than racing the kill below.
    std::thread::sleep(Duration::from_millis(500));
    let _ = subscriber.child_mut().kill();
    let _ = subscriber.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    std::thread::sleep(Duration::from_millis(200));

    let sub_captured = read_captured(&mut sub_reader);
    assert!(
        handshook,
        "the subscriber never completed a handshake through the tap, so this \
         capture holds no session for the plane to read.\n\
         --- subscriber ---\n{sub_captured}"
    );

    let segments = recording.lock().expect("recording lock").clone();
    assert!(!segments.is_empty(), "the tap recorded nothing");
    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");

    // THE POPULATION, before anything is asked of the plane. A dissection with
    // no flow or no decoded message would satisfy every soundness claim below
    // by having nothing to be unsound about — this workspace's own
    // population-of-zero rule, in the one kind of test where the population
    // depends on another process.
    let flows = dissection.flows();
    assert_eq!(flows.len(), 1, "one relayed connection is one flow");
    let decoded = flows[0].frames.len();
    assert!(
        decoded > 0,
        "the capture decoded no transport message at all:\n{sub_captured}"
    );

    // R2277 (open-debt item 613) — WHICH NAMES THIS LEG PUTS ON THE WIRE.
    // The interest plane reads declarations through `wz_capture::interest`, an
    // API that never touches this file's naming, so before this the leg's own
    // message vocabulary was unobserved: `INTEREST_LEG_NAMES` could not be derived
    // from it, and whether a stock zenohd answers a subscription with a
    // `Declare` was a guess. Now it is a reading.
    let flow = &flows[0];
    let mut transport: Vec<&'static str> = Vec::new();
    for frame in flow.frames.iter() {
        if let Ok(f) = &frame.frame {
            transport.push(frame_name(f));
        }
    }
    let (subscriber_records, subscriber_failures, subscriber_disagreements) =
        records_on(flow, Direction::A);
    let (dialer_records, dialer_failures, dialer_disagreements) = records_on(flow, Direction::B);
    eprintln!("interest leg transport names: {transport:?}");
    eprintln!("interest leg RECORD set (A): {subscriber_records:?}");
    eprintln!("interest leg RECORD set (B): {dialer_records:?}");
    assert!(
        subscriber_failures.is_empty() && dialer_failures.is_empty(),
        "the interest leg's Frames failed to decode: {subscriber_failures:?} \
         {dialer_failures:?}"
    );
    assert!(
        subscriber_disagreements.is_empty() && dialer_disagreements.is_empty(),
        "the codec decoder and the dissector disagree about the interest leg's \
         batches: {subscriber_disagreements:?} {dialer_disagreements:?}"
    );
    let mut said: Vec<&str> = transport.clone();
    said.extend(subscriber_records.iter().map(String::as_str));
    said.extend(dialer_records.iter().map(String::as_str));
    assert_named_by_the_vocabulary(&said, INTEREST_LEG_NAMES, "the interest leg's names");

    let census = wz_capture::interest::interests(&dissection);
    eprintln!(
        "interest plane over stock zenohd: {} declaration(s), {} request(s), \
         {} orphan withdrawal(s), out of {decoded} decoded message(s)",
        census.interests().len(),
        census.requests().len(),
        census.orphan_withdrawals(),
    );

    let live = flows[0].flow;
    for (at, d) in census.interests().iter().enumerate() {
        assert_eq!(
            d.flow, live,
            "declaration {at} names a flow this capture does not hold: {d:?}"
        );
        if let Some(closed) = d.withdrawn_at {
            assert!(
                closed >= d.declared_at,
                "declaration {at} was withdrawn BEFORE it was declared \
                 ({closed} < {}): {d:?}",
                d.declared_at
            );
        }
    }
    for (at, r) in census.requests().iter().enumerate() {
        assert_eq!(
            r.flow, live,
            "request {at} names a flow this capture does not hold: {r:?}"
        );
    }

    // AND THE PLANE MUST NOT HAVE INVENTED A WITHDRAWAL. An orphan withdrawal
    // is a real and honest state for a capture begun mid-session; this one
    // begins at the handshake, so nothing went past before the tap and every
    // withdrawal here must have its own declaration.
    assert_eq!(
        census.orphan_withdrawals(),
        0,
        "this capture starts at the handshake, so no withdrawal can be closing \
         something the tap missed"
    );
}

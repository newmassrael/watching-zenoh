// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2049 (open-debt item 390, the `shm` half) — `walk_shm_init_body`, against
//! bytes two stock zenoh processes actually wrote.
//!
//! ## The gap
//!
//! R311y894 gave the establishment `shm` extension a walker and judged it
//! against `wz_session_core::extshm`'s own encoder. That is producer-judged and
//! correct as far as it goes, and item 390 named what it does not reach: a
//! layout both halves of this tree get WRONG TOGETHER passes every assertion in
//! it. zenoh writes this body too, and nothing here had ever read zenoh's.
//!
//! `wz_shm_establishment_zenohd_interop` is not that witness and the difference
//! is the one the auth family had to learn twice: wz is a PARTICIPANT there, so
//! the InitSyn body on that wire is wz's own. A decoder graded against its own
//! encoder is the self-witness this axis exists to escape.
//!
//! ## The topology: no wz process at all
//!
//! `shared-memory` is absent from zenoh's `default` set, so the STOCK oracle has
//! no `Shm` ext compiled in. `ZENOHD_SHM=1 scripts/build-zenohd.sh` builds the
//! variant that does, and that variant installs `zenohd` ONLY -- no core
//! examples. So the dialer is a second zenohd rather than a `z_get`:
//!
//! ```text
//!   zenohd-shm (B) --connect ──► [tap] ──► zenohd-shm (A), listening
//!        the INITIATOR                       the ACCEPTOR
//! ```
//!
//! Both are stock zenoh. wz appears only as the reader of the synthesised pcap,
//! which is the right shape for grading a DECODER.
//!
//! ## What the two halves contribute, and why the COUNT is the discriminator
//!
//! The body has no tag saying which stage it is. Upstream declares
//! `InitSyn { alice_segment }` and `InitAck { alice_challenge, bob_segment }`
//! (`.../establishment/ext/shm.rs:162-215`), and
//! `wz_session_core::dissect::walk_shm_init_body` reads one VLE, then reads a
//! second only if bytes remain -- renaming the first when it does. So the
//! NUMBER of VLEs is the stage, exactly as the record count is for the
//! multilink walker R2048 witnessed:
//!
//! | direction | message | VLEs | what they are |
//! |---|---|---|---|
//! | B -> A | `Init`(syn) | 1 | `alice_segment` — the initiator's segment id |
//! | A -> B | `Init`(ack) | 2 | `alice_challenge`, `bob_segment` |
//!
//! A build that keyed the layout on the carrier rather than on what is left
//! would satisfy one row and fail the other.
//!
//! ## And the widths, because a count is only a shape
//!
//! `AuthSegmentID` is `u32` and `AuthChallenge` is `u64` upstream
//! (`shm.rs:36-37`). Those are foreign facts this tree did not choose, and they
//! separate "two numbers were read" from "the two numbers are the ones zenoh
//! wrote": a walker that swapped the InitAck's pair would report a segment id
//! that does not fit in 32 bits with overwhelming probability, and the two
//! segments must differ because each peer allocates its own.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_capture::Dissection;
use wz_integration_tests::common::{
    wait_for_tcp_accept_alive, zenohd_shm_binary, ChildGuard, PortReservation,
    ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_integration_tests::ext_bodies::{
    assert_no_entry_borrows_a_descendants_value, assert_witnessed_set, bodies_of, dump, Body,
    Depth, Reading, ENC_ZBUF,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Recording, Side};
use wz_session_core::passive::Direction;

/// The synthesised endpoint ports. NOT the real ones, and named because they
/// DECIDE which half `Direction::A` is — `FlowKey` orders endpoints by
/// `(addr, port)` and both are 127.0.0.1.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// How long the dialer is given to complete a handshake through the tap.
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(10);

/// The extension bodies this capture is asserted to carry, by `ext_name`.
///
/// A SET rather than a count, compared BOTH ways, and asserted BEFORE any claim
/// about a reading. MEASURED on the first run: every round of this family has
/// had its first red here, because a capture carries what it carries and not
/// what the file expected.
const WITNESSED: &[&str] = &["patch", "qos", "shm"];

/// What `walk_shm_init_body` names per stage. The three-way distinctness of
/// these sets is what lets this file state a COUNT without counting.
const INIT_SYN_FIELDS: &[&str] = &["alice_segment"];
const INIT_ACK_FIELDS: &[&str] = &["alice_challenge", "bob_segment"];

/// Spawn a stock SHM-enabled zenohd. `connect` is `None` for the acceptor.
fn spawn_shm_zenohd(bin: &std::path::Path, listen: u16, connect: Option<u16>) -> ChildGuard {
    let mut command = Command::new(bin);
    command
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{listen}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none");
    if let Some(port) = connect {
        command.arg("-e").arg(format!("tcp/127.0.0.1:{port}"));
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let who = if connect.is_some() {
        "zenohd-shm (initiator, dials the tap)"
    } else {
        "zenohd-shm (acceptor, behind the tap)"
    };
    let mut guard = ChildGuard::wrap(who, command.spawn().expect("spawn zenohd-shm"));
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), listen, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("{who}: {e}");
    }
    guard
}

/// Wait until BOTH directions have carried bytes. Polls the RECORDING rather
/// than a log line, so the marker is the same artefact the assertions read.
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

/// The one walked `shm` row on this half's `Init`.
fn shm_row<'b>(bodies: &'b [Body], direction: Direction, who: &str) -> &'b Body {
    bodies
        .iter()
        .filter(|b| b.direction == direction && b.carrier == "Init" && b.name == "shm")
        .find(|b| b.encoding == Some(ENC_ZBUF))
        .unwrap_or_else(|| {
            panic!(
                "no walked ZBuf `shm` body on {who}'s Init:\n{}",
                dump(bodies)
            )
        })
}

/// THE COUNT, AS A SET.
fn assert_stage_fields(body: &Body, want: &[&str], stage: &str, bodies: &[Body]) {
    let got: Vec<&str> = body
        .read_names()
        .into_iter()
        .filter(|n| *n != body.name)
        .collect();
    assert_eq!(
        got,
        want,
        "the {stage} `shm` body was not read as {want:?}. Nothing in this body \
         says which stage it is -- the walker reads one VLE and then a second \
         only if bytes remain -- so the NUMBER of them is the stage, and a \
         build that took the layout from the carrier would satisfy one row and \
         fail the other:\n  {}\nwhole capture:\n{}",
        body.describe(),
        dump(bodies)
    );
}

/// THE WITNESS: the SHM establishment walker, fed bytes two stock zenoh
/// processes wrote.
///
/// The `zenohd` in the name is LOAD-BEARING: Layer C0's skip-token rule reads
/// the FUNCTION name, because that is what libtest's `--skip` matches.
// This grades the DISSECTOR on foreign bytes. wz's own `extshm` producer never
// runs here, so no atom of this tree is compiled in to be proven -- the same
// judgement R2048 had to make after Layer A4 refused a claim whose feature was
// absent from the closure.
// wz-proves: none -- grades the dissector on foreign bytes; wz's extshm producer never runs
#[test]
#[ignore = "binary-dep e2e (two SHM-variant zenohd); Layer Ewirez runs via --ignored"]
fn the_shm_walker_reads_what_two_stock_zenohd_wrote() {
    let Some(bin) = zenohd_shm_binary() else {
        eprintln!(
            "skip: the SHM-variant zenohd is absent; build it with \
             `ZENOHD_SHM=1 scripts/build-zenohd.sh`"
        );
        return;
    };

    // TWO ports under ONE reservation, and this is not a micro-optimisation.
    // `PortReservation::pick` takes a process-global mutex that is NOT
    // reentrant, so calling it twice on one thread DEADLOCKS -- the library's
    // own doc on `pick_pair` says exactly that, and R2049's first run hung
    // there after printing `running 1 test`, with no output and no timeout,
    // until it was killed. Both routers listen (a zenohd always does), so this
    // test needs two ports and `pick_pair` is the one way to get them.
    let (reservation, dialer_port) = PortReservation::pick_pair();
    let acceptor_port = reservation.port();
    let mut acceptor = spawn_shm_zenohd(&bin, acceptor_port, None);

    let (proxy_port, recording) = tap_proxy(acceptor_port);

    let mut dialer = spawn_shm_zenohd(&bin, dialer_port, Some(proxy_port));

    let both = wait_for_both_directions(&recording, HANDSHAKE_BUDGET);
    std::thread::sleep(Duration::from_millis(300));
    for child in [&mut dialer, &mut acceptor] {
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
    }
    std::thread::sleep(Duration::from_millis(200));

    assert!(
        both,
        "the tap never saw both directions, so no stock SHM handshake reached it"
    );

    let segments = recording.lock().expect("recording lock").clone();

    // ── ANTI-VACUITY FIRST ────────────────────────────────────────────────
    assert!(
        !segments.is_empty(),
        "the tap recorded NOTHING -- an empty capture satisfies every field \
         assertion below"
    );
    let from_dialer: usize = segments
        .iter()
        .filter(|(s, _)| *s == Side::FromDialer)
        .map(|(_, b)| b.len())
        .sum();
    let from_listener: usize = segments
        .iter()
        .filter(|(s, _)| *s == Side::FromListener)
        .map(|(_, b)| b.len())
        .sum();
    assert!(
        from_dialer > 0 && from_listener > 0,
        "a one-way recording is not a handshake: {from_dialer} byte(s) from \
         the dialer, {from_listener} from the listener"
    );

    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(flows.len(), 1, "one relayed connection is one flow");
    let flow = &flows[0];

    // WHICH HALF IS WHICH, DERIVED.
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "the synthesised ports decide which half is Direction::A, so this test \
         pins them: the listener is the LOW endpoint here"
    );
    let (acceptor_side, initiator_side) = (Direction::A, Direction::B);

    let bodies = bodies_of(flow, Depth::Deep);
    eprintln!(
        "extension bodies two stock SHM zenohd put on this wire:\n{}",
        dump(&bodies)
    );

    // ── THE CLAIM ABOUT THE CAPTURE, BEFORE ANY CLAIM ABOUT A READING ─────
    assert_witnessed_set(
        &bodies,
        WITNESSED,
        "two stock SHM-enabled zenohd put on this wire",
    );
    assert_no_entry_borrows_a_descendants_value(&bodies);

    // ── THE TWO STAGES, BY FIELD SET ──────────────────────────────────────
    let syn = shm_row(&bodies, initiator_side, "the initiator");
    let ack = shm_row(&bodies, acceptor_side, "the acceptor");
    assert_stage_fields(syn, INIT_SYN_FIELDS, "initiator InitSyn", &bodies);
    assert_stage_fields(ack, INIT_ACK_FIELDS, "acceptor InitAck", &bodies);
    assert_ne!(
        INIT_SYN_FIELDS, INIT_ACK_FIELDS,
        "two stages that read the same are not a discriminator",
    );

    // ── THE WIDTHS, FROM UPSTREAM'S OWN TYPES ─────────────────────────────
    // `AuthSegmentID = u32`, `AuthChallenge = u64` (`shm.rs:36-37`). A walker
    // that read the InitAck's pair in the wrong order reports a "segment" that
    // does not fit in 32 bits, which is what makes this an assertion about
    // WHERE each VLE is rather than about how many there are.
    let segment = |row: &Body, name: &str| -> u64 {
        match row.reading(name) {
            Some(Reading::Number(v)) => *v,
            other => panic!("`{name}` is not a number: {other:?} in {}", row.describe()),
        }
    };
    let alice_segment = segment(syn, "alice_segment");
    let bob_segment = segment(ack, "bob_segment");
    for (what, value) in [
        ("alice_segment", alice_segment),
        ("bob_segment", bob_segment),
    ] {
        assert!(
            value <= u64::from(u32::MAX),
            "`{what}` reads as {value}, which does not fit the `AuthSegmentID = \
             u32` upstream declares -- so this VLE is not the one zenoh wrote \
             there",
        );
    }
    // Each peer allocates its OWN segment, so a walker that reported one half's
    // number on both rows -- by reading the wrong direction, or by caching --
    // satisfies everything above and fails here.
    assert_ne!(
        alice_segment,
        bob_segment,
        "both halves reported the SAME segment id, which cannot happen when \
         each end allocates its own:\n  {}\n  {}",
        syn.describe(),
        ack.describe(),
    );
}

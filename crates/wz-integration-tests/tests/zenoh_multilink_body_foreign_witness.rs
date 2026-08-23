// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2048 (open-debt item 416) — `walk_pubkey_challenge_body`, against bytes two
//! stock zenoh processes actually wrote.
//!
//! ## The gap, and what the item got wrong about its price
//!
//! One walker serves THREE carriers, because zenoh `.transmute()`s the same
//! bytes onto two extension ids: the `pubkey` method inside the `0x3` auth
//! chain, `multi_link` on `Init`'s `0x4`, and `multi_link_syn` on `Open`'s.
//! Item 396 closed the usrpwd axis and left this one open, and item 416
//! recorded the consequence precisely — one walker, so if none of the three has
//! a foreign witness then none of them does.
//!
//! It also recorded a price: an RSA keypair wired into both processes plus a
//! `known_keys_file`, with `transport/unicast/max_links > 1` as an EXTRA cost
//! on top for the multilink axis. Reading upstream turned that around, and the
//! turn is why this file exists at all:
//!
//! * `AuthPubKey::from_config` populates NO lookup set — the line where it
//!   would is `// @TODO: populate lookup file`
//!   (`.../establishment/ext/auth/pubkey.rs:123`). The acceptor then checks
//!   `!lookup.contains(&init_syn.alice_pubkey)` with NO `is_empty()` guard
//!   (`:567-569`), unlike the initiator's own check which has one (`:414-415`).
//!   So `transport/auth/pubkey/*` alone should make an acceptor that refuses
//!   every client — and that was RUN rather than left as a reading. A stock
//!   zenohd and a stock `z_get`, both given a PKCS#1 keypair by file and
//!   nothing else, produce:
//!
//!   ```text
//!   ERROR zenoh_transport::unicast::establishment::open: Received a close
//!   message (reason GENERIC) in response to an InitSyn
//!   ```
//!
//!   The client aborts. The `pubkey` CARRIER is therefore not reachable from
//!   stock config at all, which is why no test in this tree can ever feed that
//!   third carrier foreign bytes directly.
//! * `MultiLink::make` generates its OWN 512-bit keypair and calls
//!   `disable_lookup()` (`.../ext/multilink.rs:44-48`). It is the only caller
//!   of that method in the tree. So `max_links > 1` is not an extra cost on
//!   top of key wiring — it is the ONLY route to this walker through stock
//!   binaries, and it needs no key configuration whatsoever.
//!
//! `transport_multilink` is in zenoh's DEFAULT feature set (`zenoh/Cargo.toml`
//! `default`), so the stock oracle already carries it.
//!
//! ## The topology
//!
//! ```text
//!   zenoh_z_get --cfg .../max_links:2 ──► [tap] ──► zenohd --cfg .../max_links:2
//!        (stock zenoh client, INITIATOR)            (stock router, ACCEPTOR)
//! ```
//!
//! No wz process is on that wire. wz appears only as the reader of the
//! synthesised pcap, which is the right shape for grading a DECODER.
//!
//! ## What the capture contributes that no self-witness can
//!
//! The exchange is asymmetric, and the asymmetry is the whole discriminator
//! item 416 named — the walker takes no hint from the carrier and reads records
//! until the body is exhausted, so the COUNT is what separates the stages:
//!
//! | direction | message | records | what they are |
//! |---|---|---|---|
//! | client -> zenohd | `Init`(syn) | 2 | `{n, e}` — the initiator's own key |
//! | zenohd -> client | `Init`(ack) | 3 | `{n, e, challenge}` — the acceptor's key plus a nonce encrypted under the initiator's |
//! | client -> zenohd | `Open`(syn) | 1 | `{challenge}` — that nonce, re-encrypted the other way |
//! | zenohd -> client | `Open`(ack) | — | a UNIT: `multi_link_ack`, no body at all |
//!
//! A build that guessed the layout from the carrier instead of counting would
//! satisfy any one row and fail the set.
//!
//! ## And two values, because the count alone is a shape
//!
//! `KEY_SIZE` is 512 upstream (`multilink.rs:32`), and zenoh writes a public
//! key as `n.to_bytes_le()` then `e.to_bytes_le()`, each its own ZBuf
//! (`pubkey.rs:189-193`). So `pubkey_n` is 64 bytes and `pubkey_e` is the RSA
//! public exponent little-endian. Both are foreign facts this tree could not
//! have chosen, and they pin WHERE each record starts rather than only how many
//! there are.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_capture::Dissection;
use wz_integration_tests::common::{
    read_captured, wait_for_tcp_accept_alive, zenoh_core_example_binary, zenohd_binary, ChildGuard,
    PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_integration_tests::ext_bodies::{
    assert_no_entry_borrows_a_descendants_value, assert_witnessed_set, bodies_of, dump, Body,
    Depth, Reading, ENC_UNIT, ENC_ZBUF,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Recording, Side};
use wz_session_core::passive::Direction;

/// The synthesised endpoint ports. NOT the real ones, and named because they
/// DECIDE which half `Direction::A` is — `FlowKey` orders endpoints by
/// `(addr, port)` and both are 127.0.0.1. The mapping is derived and asserted
/// below rather than written down.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// Both ends need this over 1 or the extension never reaches the wire:
/// `MultiLink::make(prng, config.max_links > 1)` decides whether the FSM
/// exists at all (`unicast/manager.rs:290`), and `open()` / `accept()` take the
/// same predicate (`establishment/open.rs:620`, `accept.rs:744`).
const MAX_LINKS: &str = "2";

/// `z_get -o`, and the wall clock allowed on top. The query is scaffolding —
/// nothing answers it — because the subject is the HANDSHAKE.
const GET_TIMEOUT_MS: &str = "1500";
const GET_WALL_CLOCK: Duration = Duration::from_secs(20);

/// Upstream's multilink key size in BITS (`multilink.rs:32`), so `pubkey_n` is
/// this many bits of little-endian limbs.
const KEY_SIZE_BITS: usize = 512;

/// The extension bodies this capture is asserted to carry, by `ext_name`.
///
/// A SET rather than a count, compared BOTH ways, and asserted BEFORE any claim
/// about a reading. MEASURED on the first run, not guessed: two rounds of this
/// family (R311y900, R311y902) each had their first red here because the file
/// claimed fewer bodies than the wire held.
///
/// R2048's first run claimed `qos_link` and the wire does not carry it: this
/// exchange puts the UNIT `qos` presence marker on `Init` and the Z64 `qos` on
/// the network messages, and nothing sends the `Init` Z64 variant. Corrected by
/// the run, which is what this constant is for.
const WITNESSED: &[&str] = &[
    "multi_link",
    "multi_link_ack",
    "multi_link_syn",
    "patch",
    "qos",
    "timeout",
];

/// The record names `walk_pubkey_challenge_body` emits per stage, which is how
/// this file states a COUNT without counting: the three layouts share no field
/// set, so naming the set is strictly sharper than naming its size.
const INIT_SYN_RECORDS: &[&str] = &["pubkey_n", "pubkey_e"];
const INIT_ACK_RECORDS: &[&str] = &["pubkey_n", "pubkey_e", "challenge"];
const OPEN_SYN_RECORDS: &[&str] = &["challenge"];

/// Spawn a stock zenohd that will negotiate multilink.
fn spawn_multilink_zenohd(port: u16) -> ChildGuard {
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{port}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        .arg("--cfg")
        .arg(format!("transport/unicast/max_links:{MAX_LINKS}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guard = ChildGuard::wrap(
        "zenohd (multilink acceptor, behind the tap)",
        command.spawn().expect("spawn zenohd with max_links > 1"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("zenohd (multilink): {e}");
    }
    guard
}

/// Run a stock `z_get` as a multilink INITIATOR through `endpoint`.
fn run_multilink_zget(z_get: &std::path::Path, endpoint: &str) -> String {
    let out = tempfile::tempfile().expect("tempfile for z_get stdout");
    let out_writer = out.try_clone().expect("dup z_get stdout handle");
    let mut out_reader = out;
    let mut cmd = Command::new("stdbuf");
    cmd.args(["-oL", "-eL"]).arg(z_get).args([
        "-s",
        "demo/multilink-witness/**",
        "-o",
        GET_TIMEOUT_MS,
        "-m",
        "client",
        "-e",
        endpoint,
        "--no-multicast-scouting",
        "--cfg",
    ]);
    cmd.arg(format!("transport/unicast/max_links:{MAX_LINKS}"));
    let mut child = ChildGuard::wrap(
        "z_get (stock zenoh, multilink initiator)",
        cmd.stderr(Stdio::from(
            out_writer.try_clone().expect("dup stderr handle"),
        ))
        .stdout(Stdio::from(out_writer))
        .spawn()
        .expect("spawn z_get via stdbuf"),
    );
    let deadline = Instant::now() + GET_WALL_CLOCK;
    loop {
        match child.child_mut().try_wait().expect("try_wait on z_get") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                panic!(
                    "stock z_get did not finish within {GET_WALL_CLOCK:?}; captured:\n{}",
                    read_captured(&mut out_reader)
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    read_captured(&mut out_reader)
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

/// The one row matching `(direction, carrier, name)` that the walker read.
fn walked_row<'b>(bodies: &'b [Body], direction: Direction, carrier: &str, name: &str) -> &'b Body {
    bodies
        .iter()
        .filter(|b| b.direction == direction && b.carrier == carrier && b.name == name)
        .find(|b| b.encoding == Some(ENC_ZBUF))
        .unwrap_or_else(|| {
            panic!(
                "no ZBuf `{name}` body on {direction:?}'s {carrier}:\n{}",
                dump(bodies)
            )
        })
}

/// THE COUNT, AS A SET. The three stages of the challenge-response share one
/// walker and one extension id, and nothing in the body says which stage it is
/// — the walker reads records until the body is exhausted, so the number of
/// them IS the stage. Naming the record SET rather than its size is sharper by
/// exactly the amount that two different stages could share a count.
fn assert_stage_records(body: &Body, want: &[&str], stage: &str) {
    let got: Vec<&str> = body
        .read_names()
        .into_iter()
        .filter(|n| !n.ends_with("_len"))
        .filter(|n| *n != body.name)
        .collect();
    assert_eq!(
        got,
        want,
        "the {stage} body was not read as {want:?}. The record COUNT is what \
         separates the three stages of this exchange, and a walker that took \
         its layout from the carrier instead of counting would satisfy one row \
         and fail the others: {}",
        body.describe()
    );
}

/// THE WITNESS: the shared pubkey/multilink walker, fed bytes stock zenoh wrote
/// on both halves.
///
/// The `zenohd` in the name is LOAD-BEARING: Layer C0's skip-token rule reads
/// the FUNCTION name, because that is what libtest's `--skip` matches.
// WHY THIS DECLARES NO ATOM, which Layer A4 taught this round rather than the
// other way round.
//
// The first push claimed `session-extmultilink` (not an atom at all) and the
// second `transport-multilink`. A4 refused both, the second for the right
// reason: `transport-multilink` is NOT in this crate's enabled feature closure,
// so wz's multilink ESTABLISHMENT code is not compiled into this binary and
// cannot have been proven by it. Exactly true. What runs here is
// `wz_session_core::dissect`'s walker reading FOREIGN bytes, behind the
// `dissect` feature; wz's own producer never executes.
//
// Turning the feature on to satisfy containment would have made the claim pass
// while changing nothing about what executes, which is the vacuity A4 exists to
// catch. If the inventory ever grows an atom for the dissection surface itself,
// the line below is where it belongs.
// wz-proves: none -- grades the dissector on foreign bytes; wz's multilink producer never runs
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh z_get, multilink); Layer Ewirez runs via --ignored"]
fn the_multilink_walker_reads_what_a_stock_zenohd_handshake_wrote() {
    let z_get = zenoh_core_example_binary("z_get");
    let reservation = PortReservation::pick();
    let zenohd_port = reservation.port();
    let mut zenohd = spawn_multilink_zenohd(zenohd_port);

    let (proxy_port, recording) = tap_proxy(zenohd_port);

    let get_out = run_multilink_zget(&z_get, &format!("tcp/127.0.0.1:{proxy_port}"));

    let both = wait_for_both_directions(&recording, Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(200));
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    std::thread::sleep(Duration::from_millis(200));

    assert!(
        both,
        "the tap never saw both directions, so no stock multilink handshake \
         reached it. z_get said:\n{get_out}"
    );

    let segments = recording.lock().expect("recording lock").clone();

    // ── ANTI-VACUITY FIRST ────────────────────────────────────────────────
    assert!(
        !segments.is_empty(),
        "the tap recorded NOTHING -- an empty capture satisfies every field \
         assertion below. z_get said:\n{get_out}"
    );
    let from_client: usize = segments
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
        from_client > 0 && from_zenohd > 0,
        "a one-way recording is not a handshake: {from_client} byte(s) from \
         the client, {from_zenohd} from zenohd"
    );

    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(flows.len(), 1, "one relayed connection is one flow");
    let flow = &flows[0];

    // WHICH HALF IS WHICH, DERIVED. `low` is the lesser endpoint by
    // `(addr, port)` and zenohd is the listener, so A is the acceptor's half.
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "the synthesised ports decide which half is Direction::A, so this test \
         pins them: zenohd (the listener) is the LOW endpoint here"
    );
    let (acceptor, initiator) = (Direction::A, Direction::B);

    let bodies = bodies_of(flow, Depth::Deep);
    eprintln!(
        "extension bodies a stock zenoh multilink handshake put on this wire:\n{}",
        dump(&bodies)
    );

    // ── THE CLAIM ABOUT THE CAPTURE, BEFORE ANY CLAIM ABOUT A READING ─────
    assert_witnessed_set(
        &bodies,
        WITNESSED,
        "a stock zenoh multilink handshake put on this wire",
    );
    assert_no_entry_borrows_a_descendants_value(&bodies);

    // ── THE THREE STAGES, BY RECORD SET ───────────────────────────────────
    // This is item 416's discriminator: one walker, three layouts, and the
    // body says nothing about which it is.
    let init_syn = walked_row(&bodies, initiator, "Init", "multi_link");
    let init_ack = walked_row(&bodies, acceptor, "Init", "multi_link");
    let open_syn = walked_row(&bodies, initiator, "Open", "multi_link_syn");
    assert_stage_records(init_syn, INIT_SYN_RECORDS, "initiator InitSyn");
    assert_stage_records(init_ack, INIT_ACK_RECORDS, "acceptor InitAck");
    assert_stage_records(open_syn, OPEN_SYN_RECORDS, "initiator OpenSyn");

    // ANTI-VACUITY AS A SET: the three record sets must be DISTINCT, so a
    // capture in which one stage stood in for another cannot satisfy this by
    // repetition.
    assert_ne!(
        INIT_SYN_RECORDS, INIT_ACK_RECORDS,
        "two stages that read the same are not a discriminator",
    );
    assert_ne!(INIT_SYN_RECORDS, OPEN_SYN_RECORDS);
    assert_ne!(INIT_ACK_RECORDS, OPEN_SYN_RECORDS);

    // ── AND THE OTHER HALF OF THE ID: A UNIT WITH NO BODY ─────────────────
    // `multi_link_ack` shares `0x4` with `multi_link_syn` on `Open` and only
    // the ENCODING tells them apart, so a dispatch keyed on the id alone would
    // try to read records out of a body that does not exist.
    let ack = bodies
        .iter()
        .find(|b| b.direction == acceptor && b.name == "multi_link_ack")
        .unwrap_or_else(|| {
            panic!(
                "no `multi_link_ack` on the acceptor's half:\n{}",
                dump(&bodies)
            )
        });
    assert_eq!(
        (ack.encoding, ack.read.is_empty()),
        (Some(ENC_UNIT), true),
        "`multi_link_ack` is a UNIT and has no body to read: {}",
        ack.describe()
    );

    // ── THE VALUES, BECAUSE A COUNT IS ONLY A SHAPE ───────────────────────
    // `KEY_SIZE` is upstream's and this tree did not choose it, so the limb
    // width is a foreign fact. It pins where the FIRST record ends, which the
    // record set alone does not.
    for (row, who) in [(init_syn, "the initiator"), (init_ack, "the acceptor")] {
        match row.reading("pubkey_n") {
            Some(Reading::Bytes(n)) => assert_eq!(
                n.len(),
                KEY_SIZE_BITS / 8,
                "{who}'s multilink modulus is not {KEY_SIZE_BITS} bits, so the \
                 first record does not end where upstream's KEY_SIZE says: {}",
                row.describe()
            ),
            other => panic!("{who}'s `pubkey_n` is not raw bytes: {other:?}"),
        }
        // The RSA public exponent, little-endian, as `pubkey.rs:191` writes it.
        // A walker that read the two limbs in the wrong order, or that folded
        // the length prefix into the value, lands somewhere else here.
        match row.reading("pubkey_e") {
            Some(Reading::Bytes(e)) => {
                let mut padded = e.clone();
                padded.resize(8, 0);
                let exponent = u64::from_le_bytes(padded.try_into().expect("8 bytes"));
                assert!(
                    exponent > 2 && exponent % 2 == 1,
                    "{who}'s multilink public exponent reads as {exponent}, \
                     which is not an odd number above 2 and therefore not an \
                     RSA exponent at all: {}",
                    row.describe()
                );
            }
            other => panic!("{who}'s `pubkey_e` is not raw bytes: {other:?}"),
        }
    }

    // The challenge is ONE ciphertext block under a modulus of that same width
    // -- `alice_pubkey.encrypt(.., Pkcs1v15Encrypt, &challenge.to_le_bytes())`
    // (`pubkey.rs:577-580`). So the THIRD record's width is decided by the same
    // upstream constant as the first, which is what turns "there are three
    // records" into "each one ends where upstream says".
    for (row, who) in [
        (init_ack, "the acceptor's InitAck"),
        (open_syn, "the initiator's OpenSyn"),
    ] {
        match row.reading("challenge") {
            Some(Reading::Bytes(c)) => assert_eq!(
                c.len(),
                KEY_SIZE_BITS / 8,
                "{who} challenge is not one {KEY_SIZE_BITS}-bit RSA block: {}",
                row.describe()
            ),
            other => panic!("{who} `challenge` is not raw bytes: {other:?}"),
        }
    }

    // The two keys are DIFFERENT: each end generates its own in
    // `MultiLink::make`, so a walker that reported one half's key on both rows
    // -- by reading the wrong direction, or by caching -- passes everything
    // above and fails here.
    assert_ne!(
        init_syn.reading("pubkey_n"),
        init_ack.reading("pubkey_n"),
        "both halves reported the SAME modulus, which cannot happen when each \
         end generates its own keypair:\n  {}\n  {}",
        init_syn.describe(),
        init_ack.describe(),
    );
}

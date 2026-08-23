// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2051 (open-debt item 378) — `walk_timestamp`, against a timestamp a stock
//! zenohd actually stamped.
//!
//! ## The gap, stated as the item did
//!
//! wz does not EMIT a timestamp, so its fixtures cannot come from its own
//! encoder. The tests that exist build the body with an in-body `timestamp()`
//! helper, which proves the walker reads what that helper writes and says
//! nothing about a stock peer's bytes. Item 378 called it the interop corpus's
//! job, and it is the last member of the axis items 390 and 416 belonged to.
//!
//! ## ⚠ THE ITEM NAMES ONE CALL SITE AND THE WALKER HAS THREE
//!
//! `walk_timestamp` is reached from:
//!
//! 1. the NETWORK `timestamp` extension, id `0x2` on Push / Interest / Declare
//!    / Request / Response / Oam (`ext_name`'s `NETWORK_COMMON`),
//! 2. a `Put` body's INLINE timestamp, written when the body header's `T` flag
//!    is set (`put.rs`'s `flag::T = 1 << 5`), and
//! 3. a `Del` body's inline timestamp, the same way.
//!
//! Item 378 names (1). This round witnesses the WALKER through (2), and the
//! reason is not convenience — it is that (1) IS NOT REACHABLE from any
//! implementation in reach, which was measured rather than assumed:
//!
//! * **zenoh-rust never writes it.** Every `ext_tstamp = Some(..)` in the tree
//!   is inside a DECODER (`zenoh-codec/src/network/{push,oam,response,declare,
//!   interest,request}.rs`); no production path constructs one, and
//!   `routing/dispatcher/queries.rs:554` only forwards `msg.ext_tstamp` onward.
//!   So zenoh reads that extension and never emits it.
//! * **zenoh-pico CAN write it** — `_z_push_encode` emits it whenever
//!   `_z_timestamp_check(&msg->_timestamp)` holds
//!   (`src/protocol/codec/network.c:45,60-62`) — but only if the application
//!   sets `z_put_options_t.timestamp`, and the shipped `z_put` example never
//!   mentions a timestamp at all.
//!
//! What zenohd DOES write is (2): the router adds a timestamp to any
//! `PushBody::Put` arriving without one (`treat_timestamp!`,
//! `net/routing/dispatcher/pubsub.rs:176-205,328`). Same walker, same three
//! fields, foreign bytes. That the extension form is ABSENT is asserted here
//! too, by [`WITNESSED`] — so this file states the measured position rather
//! than quietly witnessing a different thing than the item asked for.
//!
//! ## ⚠ AND `DEFAULT_CONFIG.json5` IS NOT THE DEFAULT
//!
//! That file says `enabled: { router: true, peer: false, client: false }`
//! (`:203-211`), and this test's FIRST RUN proved a `zenohd` does not get it.
//! The field is `Option<ModeDependentValue<bool>>` with a derived `Default`
//! (`zenoh-config/src/lib.rs:533-541`), so unset reaches `unwrap_or_default!`
//! as `None` and resolves to `false` (`net/runtime/mod.rs:147`). A zenohd
//! started without `-c` prints `"timestamping":{"enabled":null}` in its own
//! startup dump — measured — and stamps nothing; the capture came back with
//! `qos` and `patch` and no timestamp anywhere. Hence
//! `--cfg timestamping/enabled:true`, and hence this paragraph: that file is a
//! DOCUMENT. Same class as `transport/auth/pubkey/known_keys_file`, which
//! parses, prints, and has no implementation behind it (R2048).
//!
//! ## The topology, and where the tap has to sit
//!
//! The stamp is added while ROUTING, so it is on the copy the router FORWARDS —
//! not on the one the publisher sent. The tap therefore goes between zenohd and
//! the SUBSCRIBER:
//!
//! ```text
//!   pico z_put  ──►  zenohd  ──►  [tap]  ──►  pico z_sub
//!   (foreign, no ts)  (stamps)               (dials the tap)
//! ```
//!
//! Two implementations and no wz process. Putting the tap on the publisher's
//! side would have captured the Put BEFORE the stamp, which is the mistake this
//! topology exists to avoid.
//!
//! ## What is held against what
//!
//! A zenoh `Timestamp` is an HLC time and the zid of whoever stamped it, and
//! the stamper here is zenohd — whose zid this test PINS on its command line.
//! So the assertion is not "some bytes were read as a zid" but "the zid in the
//! timestamp is the router this test started", the same shape R1944 used to fix
//! a face-identity test.
//!
//! The expected bytes are DERIVED from the pinned string rather than written
//! out: `ZenohIdProto::from_str` is `u128::from_str_radix(s, 16)` then
//! `uhlc::ID::try_from`, which keeps the significant LOW bytes in little-endian
//! order (`uhlc-0.8/src/id.rs:250-272`). Deriving it states the RULE, so a
//! change in that rule fails here instead of being absorbed.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_capture::Dissection;
use wz_integration_tests::common::{
    wait_for_substring, wait_for_tcp_accept_alive, zenoh_pico_cli_binary, zenohd_binary,
    ChildGuard, PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_integration_tests::ext_bodies::{assert_witnessed_set, bodies_of, dump, Depth};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Recording, Side};
use wz_session_core::dissect::{Field, FieldValue};
use wz_session_core::passive::Direction;

/// The synthesised endpoint ports. NOT the real ones, and named because they
/// DECIDE which half `Direction::A` is — `FlowKey` orders endpoints by
/// `(addr, port)` and both are 127.0.0.1.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// zenohd's zid, PINNED, because the timestamp carries whoever stamped it and
/// this is what the assertion holds that field against.
///
/// Lowercase hex with no leading zero: `ZenohIdProto::from_str` rejects
/// uppercase and `uhlc::ID::from_str` rejects a leading `0`.
const ZENOHD_ZID: &str = "a1b2c3d4";

/// The key the publisher puts on, the pattern the subscriber matches, and the
/// payload the delivery is waited for by.
const PUT_KEY: &str = "demo/timestamp/witness";
const SUB_KEY: &str = "demo/**";
const PAYLOAD: &str = "ts-witness-r2051";

/// Budgets. The subscriber must be DECLARED before the put or zenohd has no
/// route and drops the sample, so its banner is waited for rather than slept on.
const SUB_READY_BUDGET: Duration = Duration::from_secs(10);
/// How many times the put is retried, and how long each attempt waits for the
/// subscriber to report it. See the retry's own comment for why this is a
/// condition rather than a sleep.
const PUT_ATTEMPTS: usize = 6;
const PUT_ATTEMPT_BUDGET: Duration = Duration::from_secs(3);

/// The EXTENSION bodies this capture carries, by `ext_name` — and the fact
/// worth noticing is what is NOT in it.
///
/// `timestamp` is absent, and that absence is asserted rather than assumed: it
/// is the measured form of "zenoh reads the network timestamp extension and
/// never writes it". If a future zenoh starts emitting it, this list reds and
/// the module doc above becomes a question again, which is exactly what a
/// two-sided set assertion is for.
const WITNESSED: &[&str] = &["patch", "qos"];

/// The zid bytes a pinned hex string becomes on the wire.
///
/// `u128::from_str_radix(s, 16)` then `uhlc::ID::try_from`, which keeps the
/// significant LOW bytes in little-endian order. Written as the rule rather
/// than as a literal so a change to the rule reds here.
fn zid_wire_bytes(hex: &str) -> Vec<u8> {
    let n = u128::from_str_radix(hex, 16).expect("the pinned zid is hex");
    let le = n.to_le_bytes();
    let width = 16 - (n.leading_zeros() as usize) / 8;
    le[..width].to_vec()
}

/// This field's OWN child by name — never `Field::find`, which is depth-first
/// and would happily return a grandchild's homonym. R2046's lesson, one module
/// over.
fn own_child<'f>(field: &'f Field, name: &str) -> Option<&'f Field> {
    match &field.value {
        FieldValue::Nested(children) => children.iter().find(|c| c.name == name),
        _ => None,
    }
}

/// The INLINE timestamp of the first `put` body in this tree.
///
/// Depth-first for the `put` group, then that group's OWN `timestamp` child.
/// Two steps rather than one search for "timestamp", because the network
/// extension form produces a group of the same name and conflating them is the
/// whole distinction this file rests on.
fn put_timestamp<'f>(field: &'f Field) -> Option<&'f Field> {
    if field.name == "put" {
        if let Some(ts) = own_child(field, "timestamp") {
            return Some(ts);
        }
    }
    if let FieldValue::Nested(children) = &field.value {
        for child in children {
            if let Some(hit) = put_timestamp(child) {
                return Some(hit);
            }
        }
    }
    None
}

/// Spawn a stock zenohd with its zid pinned and timestamping ON.
///
/// Both `--cfg`s are load-bearing and neither is redundant with the shipped
/// `DEFAULT_CONFIG.json5`: see the module doc for why that file's
/// `{ router: true }` is not the default a `zenohd` actually runs with.
fn spawn_stamping_zenohd(port: u16) -> ChildGuard {
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{port}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        .arg("--cfg")
        .arg(format!("id:\"{ZENOHD_ZID}\""))
        .arg("--cfg")
        .arg("timestamping/enabled:true")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guard = ChildGuard::wrap(
        "zenohd (the router that stamps, behind the tap)",
        command.spawn().expect("spawn zenohd with a pinned zid"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("zenohd (stamping): {e}");
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

/// THE WITNESS: the timestamp walker, fed the stamp a stock zenohd added while
/// routing a stock pico Put.
///
/// The `zenohd` in the name is LOAD-BEARING: Layer C0's skip-token rule reads
/// the FUNCTION name, because that is what libtest's `--skip` matches.
// This grades the DISSECTOR on foreign bytes: the stamp is written by zenohd and
// wz has no producer for it at all, so there is no atom of this tree compiled in
// to be proven -- the judgement R2048 had to make after Layer A4 refused a claim
// whose feature was absent from the closure.
// wz-proves: none -- grades the dissector on foreign bytes; wz stamps nothing itself
#[test]
#[ignore = "binary-dep e2e (zenohd + two pico CLIs); Layer Ewirez runs via --ignored"]
fn the_timestamp_walker_reads_what_a_stock_zenohd_stamped() {
    let z_put = zenoh_pico_cli_binary("z_put");
    let z_sub = zenoh_pico_cli_binary("z_sub");

    let reservation = PortReservation::pick();
    let zenohd_port = reservation.port();
    let mut zenohd = spawn_stamping_zenohd(zenohd_port);

    let (proxy_port, recording) = tap_proxy(zenohd_port);

    // The SUBSCRIBER dials the tap, so the tap records zenohd's forwarded copy
    // -- the one carrying the stamp.
    // BOTH streams into the same capture, which Layer C0 refuses to let this
    // file get wrong: the capture exists because the assertions below read it
    // on failure, and a C program under test says WHY it refused on STDERR. A
    // `Stdio::null()` there would drop the stream with the answer -- Layer E
    // lost two failures that way before R311y606 found the shape, and C0 caught
    // this file doing it.
    let sub_out = tempfile::tempfile().expect("tempfile for z_sub output");
    let sub_writer = sub_out.try_clone().expect("dup z_sub stdout handle");
    let sub_err_writer = sub_out.try_clone().expect("dup z_sub stderr handle");
    let mut sub_reader = sub_out;
    let mut subscriber = ChildGuard::wrap(
        "z_sub (zenoh-pico, dials the tap)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args([
                "-m",
                "client",
                "-e",
                &format!("tcp/127.0.0.1:{proxy_port}"),
                "-k",
                SUB_KEY,
            ])
            .stdout(Stdio::from(sub_writer))
            .stderr(Stdio::from(sub_err_writer))
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    );

    // The banner upstream prints after `z_declare_subscriber` returns. Waiting
    // for it rather than sleeping is what makes the put below routable: a
    // sample with no matching subscriber is dropped by the router, and
    // `treat_timestamp!` runs only when the route is non-empty -- so an
    // unrouted sample would leave this witness with nothing AND no stamp.
    let declared = wait_for_substring(&mut sub_reader, "Press CTRL-C to quit", SUB_READY_BUDGET);
    assert!(
        declared.is_ok(),
        "z_sub never declared its subscriber, so nothing would have been routed"
    );

    // The PUBLISHER dials zenohd directly, NOT the tap: its Put has no stamp
    // yet and capturing it would witness the wrong half.
    //
    // ⚠ PUT UNTIL DELIVERED, because the banner above is a LOCAL event. It
    // fires when `z_declare_subscriber` returns in the subscriber's own
    // process; the DECLARE still has to reach zenohd and enter its routing
    // table, and until it does `get_data_route` is empty -- so the router drops
    // the sample AND never runs `treat_timestamp!`. A put that lands in that
    // window produces exactly this test's "never received" failure, which is
    // what the first run after the stderr fix hit. Retried rather than slept
    // on: a put is idempotent here, and a bounded retry is a CONDITION where a
    // sleep would only be a guess that got lucky once.
    let mut delivered = Err(String::new());
    for _ in 0..PUT_ATTEMPTS {
        let put = Command::new(&z_put)
            .args([
                "-k",
                PUT_KEY,
                "-v",
                PAYLOAD,
                "-e",
                &format!("tcp/127.0.0.1:{zenohd_port}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run z_put");
        assert!(put.success(), "z_put exited {put:?}");
        delivered = wait_for_substring(&mut sub_reader, PAYLOAD, PUT_ATTEMPT_BUDGET);
        if delivered.is_ok() {
            break;
        }
    }
    let both = wait_for_both_directions(&recording, Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(300));
    let _ = subscriber.child_mut().kill();
    let _ = subscriber.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    std::thread::sleep(Duration::from_millis(200));

    // ── ANTI-VACUITY FIRST ────────────────────────────────────────────────
    assert!(
        delivered.is_ok(),
        "the subscriber never received {PAYLOAD}, so the router never forwarded \
         the sample this witness is about -- and `treat_timestamp!` never ran"
    );
    assert!(both, "the tap never saw both directions");

    let segments = recording.lock().expect("recording lock").clone();
    assert!(!segments.is_empty(), "the tap recorded NOTHING");

    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(flows.len(), 1, "one relayed connection is one flow");
    let flow = &flows[0];

    // WHICH HALF IS WHICH, DERIVED. zenohd is the listener, so it is the LOW
    // endpoint and therefore `Direction::A` -- and it is the half that matters,
    // because it is the one that stamps.
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "the synthesised ports decide which half is Direction::A, so this test \
         pins them: zenohd (the listener) is the LOW endpoint here"
    );
    let router_side = Direction::A;

    // ── WHAT THE CAPTURE CARRIES, AS A SET, BEFORE ANY READING IS JUDGED ──
    // Including the ABSENCE of a `timestamp` EXTENSION, which is the point.
    let bodies = bodies_of(flow, Depth::Deep);
    eprintln!(
        "extension bodies a stock zenohd put on this wire while routing:\n{}",
        dump(&bodies)
    );
    assert_witnessed_set(
        &bodies,
        WITNESSED,
        "a stock zenohd put on this wire while routing a pico Put",
    );
    // ⚠ `assert_no_entry_borrows_a_descendants_value` is deliberately NOT called
    // here, and the reason is that it refused to be. Its population is UNIT
    // entries and WALKED ZBuf bodies, and this capture has neither: every row is
    // a Z64, which is entitled to a value of its own. Calling it anyway made its
    // own anti-vacuity guard fire -- `only 0 row(s) of this capture could carry
    // a borrowed value` -- which is the rule correctly refusing to report green
    // over an empty population. Left out with this note rather than called for
    // the look of it.

    // ── THE INLINE STAMP, ON THE ROUTER'S HALF ────────────────────────────
    let mut stamps: Vec<&Field> = Vec::new();
    let mut walked_trees = Vec::new();
    for frame in flow.frames.iter() {
        if frame.direction != router_side {
            continue;
        }
        let Ok(bytes) = flow.message_bytes(frame) else {
            continue;
        };
        let Ok(tree) = wz_session_core::dissect::dissect_transport_message(bytes, 0) else {
            continue;
        };
        walked_trees.push(tree);
    }
    for tree in &walked_trees {
        if let Some(ts) = put_timestamp(tree) {
            stamps.push(ts);
        }
    }
    let stamp = stamps.first().unwrap_or_else(|| {
        panic!(
            "no `put` body on the router's half carries an inline `timestamp`. \
             A zenoh router stamps every routed Put once `timestamping/enabled` \
             is on, so either the sample was not routed or the body header's T \
             flag was not read"
        )
    });

    let read = |name: &str| -> Option<&FieldValue> { own_child(stamp, name).map(|f| &f.value) };

    // The HLC time. Asserted present-and-nonzero rather than against a value,
    // because it is a clock reading -- but a zero here would mean the VLE was
    // not read at all, which is what this catches.
    match read("time") {
        Some(FieldValue::Uint(t)) | Some(FieldValue::Bits(t)) if *t > 0 => {}
        other => panic!("the stamp's HLC `time` is not a positive number: {other:?}"),
    }

    // ── AND THE ZID, AGAINST THE ROUTER THIS TEST STARTED ─────────────────
    // This is the binding that makes the reading identity rather than shape: a
    // walker that read the two fields in the wrong order, or that folded the
    // length prefix into the value, lands somewhere that is not this zid.
    let expected = zid_wire_bytes(ZENOHD_ZID);
    match read("zid") {
        Some(FieldValue::Bytes(zid)) => assert_eq!(
            zid, &expected,
            "the zid inside the stamp is not the router this test pinned \
             (`id:{ZENOHD_ZID}` -> {expected:02x?}). The stamp names WHO \
             stamped, so this is the field that says these bytes came from that \
             process and not from anywhere else"
        ),
        other => panic!("the stamp's `zid` is not raw bytes: {other:?}"),
    }
    // The length prefix must agree with the bytes it introduces -- the pair is
    // what `walk_timestamp` reads, and a length taken from the wrong place is
    // self-consistent with a value taken from the wrong place.
    match read("zid_len") {
        Some(FieldValue::Uint(n)) | Some(FieldValue::Bits(n)) => assert_eq!(
            *n as usize,
            expected.len(),
            "the zid's length prefix disagrees with the zid it introduces"
        ),
        other => panic!("the stamp's `zid_len` is not a number: {other:?}"),
    }
}

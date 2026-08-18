// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y846 — a stock zenohd, told NOTHING about wz, DISCOVERS it and opens a
//! session to it.
//!
//! The mirror of `wz_scout_zenohd_interop.rs`, and the direction that decides
//! whether wz can be dropped into a network that already exists. That leg proves
//! wz can find a zenohd; this one proves a zenohd can find wz. Until this round
//! it could not, because nothing in wz ever answered a Scout — `scouting-active`
//! and `scouting-static` are both asking paths, so a wz node was reachable only
//! by reconfiguring its neighbours, which is the one thing a drop-in replacement
//! must not require.
//!
//! ## Why zenohd's argv is the assertion
//!
//! wz binds `tcp/127.0.0.1:0` — the KERNEL picks the port. zenohd's command line
//! carries `--mode peer`, its own listener, and NOT ONE reference to wz: no
//! `-e`, no `--connect`, no config file. So the only path from wz's ephemeral
//! port to zenohd's dialer runs through the Hello wz put on the scouting group.
//! A `--scout-listen` that parsed its flag and answered nothing, or that answered
//! with a compiled-in locator, cannot produce a connection to a number it was
//! never given — which is the same discriminator R311y428 built in the other
//! direction, pointed the other way.
//!
//! ## The three assertions, each load-bearing
//!
//!   1. `SCOUT RESPONDER listening on 224.0.0.224:7446` — wz joined the group as
//!      an answerer. Without it the run below would be measuring zenohd.
//!   2. `SCOUT ANSWERED <addr>` — wz DECODED a Scout from zenohd and replied.
//!      The line is printed only from `ResponderStep::Answered`, whose sole
//!      producer is a `ScoutDecision::Answer` that passed all three gates, so it
//!      binds the claim to `answer_scout` and not to a socket that echoed.
//!   3. `face 0 UP` on the wz peer — zenohd then CONNECTED. wz was given no dial
//!      target of its own (`--peer` with no `--connect`), so a face can only be
//!      an inbound accept; and the accept can only be at the port the Hello
//!      advertised. This is the whole claim in one line: an unmodified zenoh
//!      node found a wz node and talked to it.
//!
//! Opt-in (`#[ignore]`, run-ci Layer M): zenohd is an external binary and the
//! scouting group is a real multicast socket, which is exactly the pair Layer M
//! owns. Needs the demo built with `scouting-responder` (that lane builds it).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, spawn_zenohd_multicast_scouting_with_args,
    wait_for_substring, wz_ap_demo_binary, ChildGuard,
};

const RESPONDER_NEEDLE: &str = "SCOUT RESPONDER listening on ";
const ANSWERED_NEEDLE: &str = "SCOUT ANSWERED ";
const ADVERTISED_NEEDLE: &str = "ADVERTISED SELF LOCATOR ";

// wz-proves: scouting-responder zenohd->wz
// wz-proves: scouting-multicast zenohd->wz
//
// ONE direction only, unlike the R311y428 leg which claims both. That test could
// claim `wz->zenohd` because zenohd ANSWERS only after `what.matches()`, so its
// reply witnessed its decode of wz's Scout. Here the Scout is zenohd's and the
// Hello is wz's: zenohd's consumption of that Hello is witnessed (it dials the
// advertised port), but nothing in this run makes wz consume a zenohd Scout in a
// way that proves zenohd's ENCODER — wz decoding it is the wz->wz half of the
// same parse. Claiming `wz->zenohd` here would be the fabrication the gate exists
// to prevent.
#[test]
#[ignore = "binary-dep e2e: needs zenohd (stock) + wz-ap-demo[+scouting-responder]; runs via --ignored"]
fn a_stock_zenohd_discovers_wz_by_scouting_and_dials_what_its_hello_advertised() {
    let demo = wz_ap_demo_binary();
    // A demo built before this round has no `--scout-listen` at all, so a stale
    // one does not merely weaken this proof — it reproduces the exact red the
    // test is written to detect ("a stock zenohd cannot find wz"), and the
    // diagnosis goes hunting in the responder for a defect that is in the build.
    assert_demo_binary_newer_than_sources(&demo);
    // Elapsed at each barrier, printed rather than reasoned about. libtest
    // captures this and shows it only on failure, which is exactly when the
    // question "did that step actually happen, or did it return instantly?" is
    // asked — and it is a question this file has already been wrong about once.
    let started = std::time::Instant::now();
    let mark = |what: &str| eprintln!("  [{:>7.3}s] {what}", started.elapsed().as_secs_f64());

    // wz as a linkstate PEER on an EPHEMERAL tcp port, answering scouts. The
    // `:0` is load-bearing: it is what makes the port unguessable, so zenohd
    // reaching it is evidence rather than coincidence.
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz peer stderr");
    let wz_writer = wz_stderr.try_clone().expect("dup wz stderr handle");
    let mut wz_reader = wz_stderr;
    let mut wz = ChildGuard::wrap(
        "wz-ap-demo (--peer --scout-listen)",
        Command::new(&demo)
            .arg("--peer")
            .arg("tcp/127.0.0.1:0")
            .arg("--scout-listen")
            // PER-PROCESS, and this is a correctness requirement rather than
            // hygiene. zenoh dedupes scouted peers by ZID: `connect_peer`
            // returns early with "Already connected scouted peer" when a
            // transport for that zid exists (zenoh orchestrator.rs:1032-1050).
            // So a FIXED zid means a second wz node carrying it — a leftover
            // from an earlier run, or a concurrent copy of this test — makes
            // zenohd answer "already connected" and never dial THIS one. The
            // run then fails with a healthy responder and a real Hello, which
            // is the least diagnosable shape a failure can take; it cost this
            // round a false green and a false red before it was measured.
            .arg("--zid")
            .arg(format!("7073{:04x}", std::process::id() & 0xffff))
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(wz_writer))
            .spawn()
            .expect("spawn wz-ap-demo --peer --scout-listen"),
    );

    // Readiness, in the order the node reaches it: the advertise first (the
    // locator the Hello will carry), then the group join. Waiting for the join
    // BEFORE zenohd starts is not politeness — zenohd's first Scout leaves within
    // milliseconds of startup and nothing retransmits that datagram; it re-scouts
    // on a 1s->8s backoff (`SCOUT_INITIAL_PERIOD`, zenoh orchestrator.rs:46), so a
    // missed first beacon would spend the budget rather than fail the test, which
    // is a flake and not a verdict.
    let advertised_line =
        wait_for_substring(&mut wz_reader, ADVERTISED_NEEDLE, Duration::from_secs(15));
    let advertised = advertised_line.as_ref().ok().and_then(|captured| {
        captured
            .split_once(ADVERTISED_NEEDLE)
            .map(|(_, rest)| rest.lines().next().unwrap_or("").trim().to_string())
            .filter(|s| !s.is_empty())
    });
    mark("advertise wait returned");
    let listening = wait_for_substring(&mut wz_reader, RESPONDER_NEEDLE, Duration::from_secs(15));
    mark("responder-banner wait returned");

    // A real zenohd in PEER mode. Peer is required, not decoration: a router's
    // `scouting/multicast/autoconnect` default is the EMPTY list, so a default
    // zenohd would answer scouts and never dial one
    // (`DEFAULT_CONFIG.json5:149`). A peer's is `["router", "peer"]` with
    // `autoconnect_strategy` `always` (`:162`), which is what turns a discovered
    // Hello into a connection.
    //
    // `--cfg` and not a `--mode` flag, because zenohd has none: the mode is a
    // config key and the CLI exposes it only through the generic
    // `KEY:JSON5-VALUE` pairs, so the quotes around `peer` are part of the VALUE
    // (a bare `peer` is not a JSON5 string and zenohd rejects the pair).
    //
    // NOTHING here names wz.
    let zenohd = listening.is_ok().then(|| {
        spawn_zenohd_multicast_scouting_with_args(
            "zenohd (peer, scouts and autoconnects)",
            &["--cfg", r#"mode:"peer""#],
        )
    });

    mark("zenohd spawned and ready");
    let answered = zenohd
        .as_ref()
        .map(|_| wait_for_substring(&mut wz_reader, ANSWERED_NEEDLE, Duration::from_secs(30)));
    mark("scout-answered wait returned");
    let face = answered
        .as_ref()
        .and_then(|a| a.as_ref().ok())
        .map(|_| wait_for_substring(&mut wz_reader, "face 0 UP", Duration::from_secs(30)));
    mark("face wait returned");

    if let Some((mut guard, _port)) = zenohd {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
    }
    let _ = wz.child_mut().kill();
    let _ = wz.child_mut().wait();

    assert!(
        advertised_line.is_ok(),
        "wz-ap-demo --peer never logged an advertised self locator; the Hello \
         would carry no dial hint and nothing could connect to it"
    );
    let advertised = advertised.expect("the needle carries the locator");
    assert!(
        advertised.starts_with("tcp/127.0.0.1:"),
        "expected an ephemeral tcp advertise, got {advertised:?}"
    );
    let banner = match &listening {
        Ok(captured) => captured.clone(),
        Err(e) => panic!(
            "wz-ap-demo --scout-listen never joined the scouting group ({e}); \
             without the join there is no responder and this run would be \
             measuring zenohd alone"
        ),
    };
    // The banner must name the DEFAULT group, because that is where an
    // unconfigured zenohd looks. A responder listening somewhere else is
    // perfectly healthy and completely undiscoverable.
    assert!(
        banner.contains("224.0.0.224:7446"),
        "the responder must join zenoh's default scouting socket; banner: {}",
        banner.lines().next().unwrap_or("")
    );

    match &answered {
        Some(Ok(_)) => {}
        _ => panic!(
            "wz never answered a Scout. zenohd was running with multicast \
             scouting on the same group and re-scouts on a 1s->8s backoff, so \
             within the budget it certainly asked; a missing answer means the \
             Scout was received and refused, or never decoded. wz advertised \
             {advertised}"
        ),
    }
    match &face {
        Some(Ok(captured)) => {
            // The face is an INBOUND accept: this wz peer was given no dial
            // target at all, so it originated no connection. But "a face came
            // up" is not yet "a ZENOHD came up", so the line's own zid is read:
            // wz's demo zids are 4 bytes (8 hex chars, `7073….`) and zenohd's is
            // a random 16-byte ZenohIdProto (32 hex chars). A stray wz node on
            // the group could otherwise stand in for the foreign witness — which
            // is not hypothetical: a leftover wz peer is exactly what made this
            // test read wrong once already.
            let line = captured
                .lines()
                .find(|l| l.contains("face 0 UP"))
                .expect("the needle matched, so the line is in the capture");
            let zid = line
                .split_once("zid ")
                .and_then(|(_, rest)| rest.split(')').next())
                .map(str::trim)
                .unwrap_or_default();
            assert_eq!(
                zid.len(),
                32,
                "the face that came up must be a zenohd's (a 16-byte ZenohIdProto), \
                 not another wz node's short demo zid; the line was: {line}"
            );
            assert!(
                line.contains("whatami Some(Peer)"),
                "the connecting node must present itself as a peer, which is the \
                 mode its autoconnect default came from: {line}"
            );
        }
        _ => panic!(
            "a stock zenohd answered-and-then-did-not-connect: wz sent its Hello \
             advertising {advertised} but no face came up. The Hello reached \
             zenohd's scouting socket (it is what makes wz's SCOUT ANSWERED line \
             possible), so the failure is downstream — either the advertised \
             locator is not one zenoh can dial, or the accept side refused it"
        ),
    }
}

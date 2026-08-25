// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz <-> zenohd MULTILINK aggregation cross-impl interop (R311y472).
//!
//! `transport-multilink` is zenoh's N-physical-links-into-ONE-logical-session
//! aggregation: a peer whose `transport/unicast/max_links` budget is `> 1`
//! builds `MultiLink` establishment state, offers the 0x4 ext carrying an
//! ephemeral RSA pubkey, and thereafter admits a further link from an
//! already-known zid onto the SAME transport instead of refusing it.
//!
//! Until this round the wz side had a full behavioural lane (C1ba: slice-1
//! join, the deploy-active accept AND dial paths, per-link auto-re-add, the
//! qos x multilink priority segregation) and its atom reason named the gap
//! precisely — *"S4: only wz<->wz aggregation e2e exist, no wz<->zenohd byte
//! interop"*. Layer A4 counted the atom UNPROVEN for exactly that reason. This
//! leg is that claim's first foreign witness.
//!
//! ## Why the verdict is READ OFF ZENOH, not off wz
//!
//! wz logs `link AGGREGATED to zid <z> (live links now 2)` when it believes it
//! aggregated. That line is worth nothing as proof: it is wz's own arithmetic
//! over wz's own session table, and it would print identically if the 0x4 ext
//! on the wire were garbage that zenoh happened to tolerate. The same trap the
//! `unixsock_acceptor` leg fell into in R311y470-y471 — a test that composes
//! the same value for BOTH sides proves the LINK and says nothing about either
//! side's CHOICE.
//!
//! So the assertion here is on ZENOH's OWN REPORT. zenohd's adminspace answers
//! `@/<zid>/router` with, among other things:
//!
//! ```text
//! "sessions":[{"links":[{"dst":"tcp/…","src":"tcp/…"},
//!                       {"dst":"tcp/…","src":"tcp/…"}],
//!              "peer":"2007370","weight":null,"whatami":"peer"}]
//! ```
//!
//! — one session object per TRANSPORT, carrying the physical links zenoh has
//! bound to it. Two links under ONE session object, for wz's zid, is zenoh
//! stating that it aggregated; it is not reachable by any amount of wz-side
//! bookkeeping. The GET that reads it is itself a second wz process
//! (`--query`), so the leg needs no third stack.
//!
//! ## The two legs
//!
//!   1. the PROOF. zenohd runs `transport/unicast/max_links:2`; wz runs as a
//!      linkstate `--peer` with `--max-links 2` and the SAME dial target listed
//!      twice, so it opens two TCP links to one zid. zenoh reports ONE session
//!      for wz carrying TWO links.
//!   2. the TWIN. The SAME wz argv against a STOCK zenohd (`max_links` not
//!      configured; the knob defaults to 1). zenoh reports ONE session for wz
//!      carrying ONE link, and wz's second dial is refused outright. This is
//!      what makes leg 1 a discriminator instead of a tautology: the count
//!      zenoh reports tracks the ROUTER's budget, so it cannot be a wz-side
//!      fiction, and it cannot be a hardcoded 2.
//!
//! Both legs pin the peer id, so the session is bound to THIS wz node rather
//! than to whatever session happens to be first in the array — and a rendering
//! change reds loudly here instead of silently matching nothing.
//!
//! The adminspace PARSER and its calibration units live in this crate's lib
//! (`parse_zenoh_admin_sessions`), not here. Layer C0's binary-dep discipline
//! requires every test fn in a spawning `tests/` file to be `#[ignore]`d, and a
//! measuring instrument whose calibration never runs is not calibrated; in the
//! lib the units run in the ordinary Layer C1 workspace lane.
//!
//! (That sentence is deliberately not written with the attribute spelled out:
//! Layer C0's scanner arms on ANY line matching the test attribute and then
//! binds to the next `fn`, so quoting it in prose makes the following helper
//! look like an un-skippable test fn. Measured — it reds C0.)
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd is an external binary.
//! Serialized with the other zenohd legs (`--test-threads=1`).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    demo_log_filter, line_with, parse_zenoh_admin_sessions, spawn_on_ephemeral_port,
    spawn_zenohd_multilink_on_ephemeral_tcp, spawn_zenohd_on_ephemeral_tcp, wait_for_substring,
    wz_ap_demo_binary, ChildGuard, ZenohSession,
};

/// The wz peer's PINNED routing zid, as passed to `--zid`.
const WZ_PEER_ZID_ARG: &str = "70730002";

/// The same zid AS ZENOH RENDERS IT in its adminspace reply.
///
/// zenoh's `ZenohId` Display emits the id's bytes in the REVERSE order wz's
/// `--zid` hex takes them, and drops the resulting leading zero nibble:
/// `70 73 00 02` -> `02 00 73 70` -> `2007370`. Pinned as an observed value
/// rather than recomputed, and paired below with a `whatami:"peer"` selection
/// so a divergence names itself instead of matching nothing and passing.
const WZ_PEER_ZID_AS_ZENOH_RENDERS: &str = "2007370";

/// The needle the wz peer emits once it has joined a second physical link onto
/// an existing session.
///
/// NOT the proof, and deliberately not asserted before it. Leg 1 checks zenoh's
/// count FIRST and carries this line into that failure message, so a red says
/// which of "wz never tried" and "wz tried, zenoh refused" happened without
/// letting the wz-side claim decide the outcome. Its own assertion runs AFTER
/// the verdict, where it catches the reverse disagreement.
const WZ_AGGREGATED_NEEDLE: &str = "link AGGREGATED to zid";

/// GET `@/*/router` off a live zenohd with a wz `--query` client and return the
/// reply body zenoh sent, unescaped.
///
/// The querier is a THIRD process on purpose: reading the aggregation off the
/// aggregating peer's own session would be the wz-side bookkeeping this leg
/// refuses to trust. It connects as a plain client, so it appears in the reply
/// as its own `whatami:"client"` session and cannot be mistaken for the peer.
///
/// The name carries the `zenohd` family token even though this is a helper, not
/// a test: Layer C0's scanner binds a test attribute on any preceding line to
/// the next `fn`, so a token-carrying name is immune to that by construction.
fn zenohd_admin_report(port: u16) -> String {
    const REPLY_NEEDLE: &str = "REPLY RECEIVED";
    let demo = wz_ap_demo_binary();
    let stderr = tempfile::tempfile().expect("tempfile for admin querier stderr");
    let writer = stderr.try_clone().expect("dup admin querier stderr handle");
    let mut reader = stderr;
    let mut querier = ChildGuard::wrap(
        "wz-ap-demo (zenohd adminspace querier)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--query")
            .arg("@/*/router")
            .arg("--on-query-reply-log")
            .env("RUST_LOG", demo_log_filter())
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo adminspace querier"),
    );
    let captured = wait_for_substring(&mut reader, REPLY_NEEDLE, Duration::from_secs(20));
    let _ = querier.child_mut().kill();
    let _ = querier.child_mut().wait();
    let captured = captured.unwrap_or_else(|e| {
        panic!("zenohd never answered the @/*/router adminspace GET: {e}");
    });
    let line = line_with(&captured, REPLY_NEEDLE)
        .unwrap_or_else(|| panic!("no {REPLY_NEEDLE} line in the querier capture:\n{captured}"));
    // The payload is Debug-formatted into the log line, so its quotes arrive
    // escaped. Nothing else in the body is escaped (locators and zids are plain
    // ASCII), so undoing `\"` is the whole of it.
    line.replace("\\\"", "\"")
}

/// Run the SHARED fixture against `port`: a `--max-links 2` wz peer that dials
/// the SAME zenohd twice, then zenoh's own account of the result. The only
/// difference between the proof and its twin is which zenohd the port belongs
/// to, so the twin is a twin by construction rather than by two copies kept in
/// step by hand.
fn aggregate_two_dials_against(port: u16) -> (Vec<ZenohSession>, Option<String>) {
    let demo = wz_ap_demo_binary();
    let target = format!("127.0.0.1:{port}");
    let stderr = tempfile::tempfile().expect("tempfile for wz peer stderr");
    let (mut peer, mut reader, _peer_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--peer",
            "127.0.0.1:0",
            // The same target LISTED TWICE is what makes the peer open two
            // physical links to one zid; `--max-links 2` is what lets the
            // second one be a JOIN rather than a fresh session.
            "--connect",
            &format!("{target},{target}"),
            "--max-links",
            "2",
            "--zid",
            WZ_PEER_ZID_ARG,
        ],
        "peer: listening on 127.0.0.1:",
        "wz peer (--max-links 2)",
        stderr,
    );

    // Barrier: a link to THIS router is up before anything is asked of zenoh.
    //
    // The needle names the peer ADDRESS and not a face INDEX on purpose. The two
    // dials race, so either can be the survivor — measured: the twin came up on
    // `face 1 UP` with `face 0 FAILED`, which a `face 0 UP` needle reads as a dead
    // node. Naming the address also stops a face to some OTHER peer from passing
    // this off as readiness.
    let face_needle = format!(" UP (peer {target}");
    let face_up = wait_for_substring(&mut reader, &face_needle, Duration::from_secs(20));
    // The wz-side aggregation claim, captured but NOT asserted on here — the
    // caller decides what it means, and in the twin its ABSENCE is expected.
    let aggregated = wait_for_substring(&mut reader, WZ_AGGREGATED_NEEDLE, Duration::from_secs(10))
        .ok()
        .and_then(|c| line_with(&c, WZ_AGGREGATED_NEEDLE));

    let sessions = face_up
        .as_ref()
        .map(|_| parse_zenoh_admin_sessions(&zenohd_admin_report(port)))
        .unwrap_or_default();

    let _ = peer.child_mut().kill();
    let _ = peer.child_mut().wait();
    // Carry the peer's own capture into the diagnosis: a "no face" red is ambiguous
    // between a refused dial, a mis-parsed flag and a dead router, and the log says
    // which.
    if let Err(captured) = &face_up {
        panic!(
            "the wz peer never brought a face up against zenohd on 127.0.0.1:{port}\n\
             --- captured wz peer stderr ---\n{captured}"
        );
    }
    (sessions, aggregated)
}

/// Select the ONE session zenoh reports with `whatami:"peer"` — the wz mesh
/// node. Every other participant (the readiness probe, the adminspace querier)
/// connects as a `client`, so this is unambiguous, and asserting the count
/// stops a second stray peer from being silently skipped over.
fn the_peer_session(sessions: &[ZenohSession]) -> &ZenohSession {
    let peers: Vec<&ZenohSession> = sessions.iter().filter(|s| s.whatami == "peer").collect();
    assert_eq!(
        peers.len(),
        1,
        "expected exactly ONE whatami=peer session in zenoh's adminspace reply, got {peers:?} \
         (full reply: {sessions:?})"
    );
    let session = peers[0];
    assert_eq!(
        session.peer, WZ_PEER_ZID_AS_ZENOH_RENDERS,
        "zenoh reported a peer session whose zid is not the one wz was pinned to \
         (--zid {WZ_PEER_ZID_ARG}); either another peer joined this router or zenoh's \
         zid rendering moved"
    );
    session
}

/// LEG 1 — the proof. A `max_links:2` zenohd, dialed twice by ONE wz zid,
/// reports ONE session carrying TWO links.
// wz dials zenohd (twice), so the direction is `wz->zenohd` by the corpus
// convention of who DIALS.
// wz-proves: transport-multilink wz->zenohd
#[test]
#[ignore = "binary-dep e2e: needs zenohd + wz-ap-demo[+routing-peer,transport-multilink]; runs via --ignored"]
fn zenohd_aggregates_two_wz_links_into_one_session() {
    let (zenohd, port) = spawn_zenohd_multilink_on_ephemeral_tcp(2, || {
        tempfile::tempfile().expect("tempfile for zenohd readiness probe stderr")
    });
    let (sessions, aggregated) = aggregate_two_dials_against(port);
    let mut zenohd = zenohd;
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // THE VERDICT, and it is zenoh's: one transport, two physical links. Asserted
    // FIRST, and deliberately so. An earlier draft gated on wz's own JOIN log and
    // was measured against a damaged 0x4 ext id: wz then correctly declines to
    // claim aggregation, so the wz-side check fired and the zenoh-side one was
    // never reached — the verdict assertion was unreachable under every wire
    // damage available. Ordering it first makes the RED land on what this leg
    // exists to measure; wz's own claim rides along in the message, so a failure
    // still separates "wz never tried" from "wz tried, zenoh refused".
    let session = the_peer_session(&sessions);
    assert_eq!(
        session.links, 2,
        "zenoh bound {} link(s) to wz's session, not 2 — the 0x4 MultiLink ext did not \
         carry across, so zenoh treated the second dial as something other than a JOIN.\n\
         wz's own JOIN line was: {aggregated:?}\n\
         zenoh's full report: {sessions:?}",
        session.links
    );

    // The reverse disagreement, which the count alone cannot catch: zenoh
    // aggregated but wz did not register the join on its side.
    let aggregated = aggregated.expect(
        "zenoh reports TWO links on one session, but the wz peer never logged a \
         multilink JOIN — the aggregation is one-sided",
    );
    assert!(
        aggregated.contains("live links now 2"),
        "wz logged a JOIN that did not reach 2 live links while zenoh bound 2: {aggregated}"
    );
}

/// LEG 2 — the twin. The SAME wz argv against a STOCK zenohd, whose
/// `max_links` defaults to 1: zenoh reports ONE link, so leg 1's count is
/// reading the ROUTER's budget rather than restating wz's.
// wz-proves: none -- the CALIBRATION twin of the leg above. An aggregation that
// correctly does NOT happen witnesses no atom's cross-impl behaviour; its whole job
// is to show that the sibling's link count tracks the router's budget.
#[test]
#[ignore = "binary-dep e2e: needs zenohd + wz-ap-demo[+routing-peer,transport-multilink]; runs via --ignored"]
fn stock_zenohd_refuses_the_second_link_and_reports_one() {
    let (zenohd, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for zenohd readiness probe stderr")
    });
    let (sessions, aggregated) = aggregate_two_dials_against(port);
    let mut zenohd = zenohd;
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    assert_eq!(
        aggregated, None,
        "wz reported a multilink JOIN against a router whose max_links is 1; either the \
         stock default moved or wz aggregated without the router's consent"
    );
    let session = the_peer_session(&sessions);
    assert_eq!(
        session.links, 1,
        "a stock zenohd bound {} link(s) to wz's session; with max_links=1 it must refuse \
         the second dial, and if it does not, leg 1's assertion is not a discriminator \
         (zenoh's full report: {sessions:?})",
        session.links
    );
}

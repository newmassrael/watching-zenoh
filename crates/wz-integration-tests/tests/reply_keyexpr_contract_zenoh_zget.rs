// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `reply ⊆ query` contract on a wire a stock zenoh querier reads.
//!
//! ## The claim under test
//!
//! Both references refuse, at the RESPONDER, a reply whose keyexpr does not
//! intersect the query's, unless the query carried `_anyke`:
//! `zenoh/src/api/queryable.rs` @ `which does not intersect with query`. wz's
//! responder does the same and returns the refusal to the handler that asked.
//! Its own tests prove that against wz's own querier, which reads `_anyke` the
//! same way wz writes it — a shared misreading would pass them. This file puts
//! a stock zenoh `z_get` on the other end.
//!
//! ## Why the refusal is observable at all
//!
//! A stock querier drops an out-of-query reply ITSELF, so "the reply never
//! printed" cannot tell a wz refusal from a zenoh drop. What separates them is
//! that the zenoh drop is LOGGED:
//! `zenoh/src/api/session.rs` @ `which didn't match query`. With `RUST_LOG=warn`
//! on the querier, a wz responder that let the reply onto the wire leaves that
//! warning behind; one that refused it leaves nothing. The wz side logs each
//! key's verdict, so the two halves are read from their own processes.
//!
//! ## The two legs
//!
//! One wz queryable on `demo/rq/**` answers every query under two keys: one
//! inside the pattern and one outside it.
//!
//! 1. A default `z_get`: the inside reply arrives, the outside one is refused by
//!    wz, and zenoh logs no drop.
//! 2. The same `z_get` with `?_anyke`: both arrive. This is the leg that makes
//!    the first one mean something — it shows the outside key is deliverable
//!    through this router to this querier when the query allows it, so its
//!    absence in leg 1 is the responder's decision.
//!
//! ## What this does not witness
//!
//! wz's REQUESTER-side refusal. No stock responder emits an out-of-query reply
//! to a query without `_anyke` — its own responder gate refuses first — so
//! against a conforming foreign queryable that refusal has no input to act on.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, run_query_until_answered,
    spawn_zenohd_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary,
    zenoh_core_example_binary, ChildGuard, QueryAttempts,
};

const QABL_PATTERN: &str = "demo/rq/**";
const KEY_INSIDE: &str = "demo/rq/inside";
const KEY_OUTSIDE: &str = "other/outside";
const PAYLOAD: &str = "reply-keyexpr-contract";

/// zenoh's own requester-side drop, logged at `warn`.
const ZENOH_DROP: &str = "didn't match query";

const GET_TIMEOUT_MS: &str = "3000";
const GET_WALL_CLOCK: Duration = Duration::from_secs(15);
/// The declaration-propagation window: an attempt that missed the route is
/// finalized at once and costs milliseconds.
const GET_ATTEMPTS: usize = 6;

fn tempfile() -> File {
    tempfile::tempfile().expect("tempfile")
}

fn received(key: &str) -> String {
    format!(">> Received ('{key}': '{PAYLOAD}')")
}

/// The wz queryable, connected straight to zenohd, answering under both keys.
fn spawn_wz_queryable(zenohd_port: u16) -> (ChildGuard, File) {
    let demo = wz_ap_demo_binary();
    // A stale demo answers from code that predates the round, which is the one
    // way a leg could pass while measuring yesterday's build.
    assert_demo_binary_newer_than_sources(&demo);
    let out = tempfile();
    let writer = out.try_clone().expect("dup wz-ap-demo stderr");
    let mut reader = out;
    let child = ChildGuard::wrap(
        "wz-ap-demo (--queryable --reply-keyexpr x2)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{zenohd_port}"))
            .arg("--queryable")
            .arg(QABL_PATTERN)
            .arg("--reply")
            .arg(PAYLOAD)
            .arg("--reply-keyexpr")
            .arg(KEY_INSIDE)
            .arg("--reply-keyexpr")
            .arg(KEY_OUTSIDE)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );
    if let Err(captured) = wait_for_substring(
        &mut reader,
        "DECLARED ROUTED QUERYABLE",
        Duration::from_secs(15),
    ) {
        panic!("the wz queryable never declared:\n{captured}");
    }
    (child, reader)
}

fn spawn_zget(zenohd_port: u16, selector: &str) -> (ChildGuard, File) {
    let out = tempfile();
    let writer = out.try_clone().expect("dup z_get output handle");
    let child = ChildGuard::wrap(
        "z_get (stock zenoh)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(zenoh_core_example_binary("z_get"))
            .args([
                "-s",
                selector,
                "-o",
                GET_TIMEOUT_MS,
                "-m",
                "client",
                "-e",
                &format!("tcp/127.0.0.1:{zenohd_port}"),
                "--no-multicast-scouting",
            ])
            // `warn`, not the example's `error` default: the requester's own drop
            // is the discriminator and it is logged at warn.
            .env("RUST_LOG", "warn")
            .stderr(Stdio::from(writer.try_clone().expect("dup stderr")))
            .stdout(Stdio::from(writer))
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );
    (child, out)
}

/// The whole of one querier's output, read after it EXITED: a reply that
/// arrives after the first one is only in the capture once the query is over,
/// and so is zenoh's warning about a dropped one.
fn run_get(zenohd_port: u16, selector: &str) -> String {
    let answered = run_query_until_answered(
        "stock z_get through zenohd",
        QueryAttempts::UpTo(GET_ATTEMPTS),
        &received(KEY_INSIDE),
        GET_WALL_CLOCK,
        || spawn_zget(zenohd_port, selector),
    );
    let (mut child, mut reader, _) = answered.unwrap_or_else(|captured| {
        panic!(
            "`{selector}`: the in-query reply never arrived in {GET_ATTEMPTS} attempts, so the \
             query did not reach the wz queryable and nothing below would be measured\n\
             --- z_get ---\n{captured}"
        )
    });
    let deadline = Instant::now() + GET_WALL_CLOCK;
    loop {
        match child.child_mut().try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => panic!(
                "`{selector}`: z_get did not finish its query within {GET_WALL_CLOCK:?}\n\
                 --- z_get ---\n{}",
                read_captured(&mut reader)
            ),
        }
    }
    read_captured(&mut reader)
}

/// Leg 1 — a default query. wz refuses the outside key at its responder, and
/// zenoh therefore never has one to drop.
// wz-proves: query-get wz->zenoh
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh z_get + wz-ap-demo); Layer Z runs via --ignored"]
fn a_default_zenoh_zget_never_sees_a_wz_reply_outside_its_query() {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let (_wz, mut wz_out) = spawn_wz_queryable(port);

    let get_out = run_get(port, QABL_PATTERN);
    let wz_log = read_captured(&mut wz_out);
    let ctx = format!("--- z_get ---\n{get_out}\n--- wz ---\n{wz_log}");

    assert!(
        wz_log.contains(&format!("QUERYABLE REPLY ADMITTED keyexpr='{KEY_INSIDE}'")),
        "wz did not admit the in-query key, so the refusal below has no control\n{ctx}"
    );
    assert!(
        wz_log.contains(&format!("QUERYABLE REPLY REFUSED keyexpr='{KEY_OUTSIDE}'")),
        "wz did not refuse the out-of-query key for a query without `_anyke`\n{ctx}"
    );
    assert!(
        !get_out.contains(ZENOH_DROP),
        "zenoh logged dropping a reply, so wz put the out-of-query key on the wire and \
         the querier's own gate caught it instead of wz's responder\n{ctx}"
    );
    assert!(
        !get_out.contains(KEY_OUTSIDE),
        "the out-of-query key reached the zenoh querier\n{ctx}"
    );
}

/// Leg 2 — the same query with `_anyke`. Both keys arrive, which is what binds
/// leg 1's absence to wz's refusal rather than to the route.
// wz-proves: query-get wz->zenoh
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh z_get + wz-ap-demo); Layer Z runs via --ignored"]
fn an_anyke_zenoh_zget_receives_a_wz_reply_outside_its_query() {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let (_wz, mut wz_out) = spawn_wz_queryable(port);

    let get_out = run_get(port, &format!("{QABL_PATTERN}?_anyke"));
    let wz_log = read_captured(&mut wz_out);
    let ctx = format!("--- z_get ---\n{get_out}\n--- wz ---\n{wz_log}");

    assert!(
        wz_log.contains(&format!("QUERYABLE REPLY ADMITTED keyexpr='{KEY_OUTSIDE}'")),
        "wz did not read zenoh's `_anyke` and refused the out-of-query key\n{ctx}"
    );
    assert!(
        !wz_log.contains("QUERYABLE REPLY REFUSED"),
        "wz refused a reply to a query that accepts any key\n{ctx}"
    );
    assert!(
        get_out.contains(&received(KEY_OUTSIDE)),
        "the out-of-query key never reached the zenoh querier that asked for it\n{ctx}"
    );
}

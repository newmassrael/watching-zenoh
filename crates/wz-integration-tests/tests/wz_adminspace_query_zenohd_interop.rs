// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y714 ([REDACTED-REQ]) — the ACTIVE adminspace query, witnessed against a real
//! zenohd, as the claim it is rather than as a side-oracle for something else.
//!
//! # Why this file exists when the capability already worked
//!
//! It was recorded for several rounds as not started, and blocked on a broken
//! premise: `adminspace.enabled` defaults to false and only zenohd forces it
//! on, so a customer's application nodes have nothing to answer. Both halves
//! were checked here, and the note was half wrong in the way a note usually is.
//!
//! The premise is true and it is not a blocker: a deployment HAS a router, the
//! router answers, and what it answers is exactly the runtime node information
//! the requirement asks for. The capability was not missing either —
//! `wz_multilink_aggregation_zenohd_interop` has queried `@/*/router` since it
//! was written, using the reply to check something else entirely. So the gap
//! was never the code; it was that nothing asserted the ADMINSPACE ANSWER as
//! the thing being proved, which is the only reason a capability shows up in
//! an audit as absent.
//!
//! Measured live before this file was written, against
//! `target/zenohd/zenohd` on a loopback listener: `@/**` returns
//! `@/<zid>/router` carrying the router's zid, its locators, its live sessions
//! with each peer's `whatami`, and its version — plus
//! `@/<zid>/router/linkstate/routers`, which is the router graph.
//!
//! # What this does NOT prove
//!
//! That an ordinary application node answers. It does not, by default, and
//! that is a fact about the deployment rather than about this reader — a
//! proposal that promises otherwise is promising a router.

use std::process::{Command, Stdio};
use std::time::Duration;
use wz_integration_tests::common::{
    demo_log_filter, spawn_zenohd_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary,
    ChildGuard,
};

/// How long the querier is given to receive a reply. Generous: the assertion
/// is about WHAT comes back, and a tight budget would turn a slow machine into
/// a failure that reads like a missing feature.
const REPLY_BUDGET: Duration = Duration::from_secs(20);

/// R311y714 ([REDACTED-REQ]) — a wz node asks a real router's admin space and learns
/// who that router is, where it listens, and who is connected to it.
// wz-proves: adminspace-read wz->zenohd
#[test]
#[ignore = "binary-dep e2e: needs zenohd + wz-ap-demo[+query-get]; runs via --ignored"]
fn zenohd_answers_an_active_adminspace_query_with_its_node_information() {
    let (mut zenohd, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for zenohd readiness probe stderr")
    });
    let captured = query_admin(port, "@/*/router");
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let reply = captured
        .lines()
        .find(|l| l.contains("REPLY RECEIVED"))
        .unwrap_or_else(|| panic!("no reply from the admin space:\n{captured}"));

    // The keyexpr is the admin space's own, and its middle chunk is the
    // router's zid — the identity `wz-capture`'s node plane reads off the
    // wire, here obtained by ASKING instead of by observing.
    assert!(
        reply.contains("@/") && reply.contains("/router"),
        "the reply must come from the admin space: {reply}"
    );
    // The runtime node information the requirement names. Asserted field by
    // field rather than by length: a reply that arrived and carried nothing
    // useful would pass any "we got an answer" check.
    for field in [
        "\\\"zid\\\"",
        "\\\"locators\\\"",
        "\\\"sessions\\\"",
        "\\\"whatami\\\"",
    ] {
        assert!(
            reply.contains(field),
            "the router's own report must carry {field}: {reply}"
        );
    }
    // And the querier itself is IN it: a client that asks is a session the
    // router knows about, so the answer describes a topology this run is part
    // of rather than an empty one.
    assert!(
        reply.contains("client"),
        "the asking node must appear as a session on the router: {reply}"
    );
}

/// R311y714 ([REDACTED-REQ]) — the router's LINK STATE, which is the observed
/// topology a canvas would overlay.
///
/// A separate key and a separate claim: `@/<zid>/router` is who this router is,
/// and this is what it can reach. The requirement asks for the second, and a
/// test that only proved the first would report an overlay it cannot draw.
// wz-proves: adminspace-router-linkstate wz->zenohd
#[test]
#[ignore = "binary-dep e2e: needs zenohd + wz-ap-demo[+query-get]; runs via --ignored"]
fn zenohd_answers_an_active_query_with_its_link_state_graph() {
    let (mut zenohd, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for zenohd readiness probe stderr")
    });
    let captured = query_admin(port, "@/*/router/linkstate/**");
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let reply = captured
        .lines()
        .find(|l| l.contains("REPLY RECEIVED"))
        .unwrap_or_else(|| panic!("no link-state reply:\n{captured}"));
    assert!(
        reply.contains("linkstate"),
        "the reply must be the link-state resource: {reply}"
    );
    // zenohd renders it as a DOT graph, and the router names itself as a
    // vertex. One router alone is a one-vertex graph, which is the honest
    // answer for this fixture and still proves the shape is a graph.
    assert!(
        reply.contains("graph"),
        "and it must be a graph rather than a scalar: {reply}"
    );
}

/// Run one query against the admin space and return the querier's log.
///
/// The querier is a plain `wz-ap-demo` client: the point of the requirement is
/// that a wz node can ASK, so the fixture must not reach for anything the
/// shipped binary does not have.
fn query_admin(port: u16, selector: &str) -> String {
    let demo = wz_ap_demo_binary();
    let stderr = tempfile::tempfile().expect("tempfile for querier stderr");
    let writer = stderr.try_clone().expect("dup querier stderr handle");
    let mut reader = stderr;
    let mut querier = ChildGuard::wrap(
        "wz-ap-demo (adminspace querier)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--query")
            .arg(selector)
            .arg("--on-query-reply-log")
            .arg("--on-query-final-log")
            .env("RUST_LOG", demo_log_filter())
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo adminspace querier"),
    );
    let captured = wait_for_substring(&mut reader, "REPLY RECEIVED", REPLY_BUDGET);
    let _ = querier.child_mut().kill();
    let _ = querier.child_mut().wait();
    captured.unwrap_or_else(|e| panic!("no adminspace reply within the budget: {e}"))
}

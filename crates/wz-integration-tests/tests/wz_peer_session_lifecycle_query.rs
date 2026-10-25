// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session lifecycle as a QUERY, over the wire between real nodes: a GET
//! closes the session with a peer and is answered with a verdict, a GET reads the
//! session's links before it, and a GET lists the verbs the node has.
//!
//! `wz-session-core`'s `lifecycle_query` and `wz-runtime-tokio`'s
//! `session_close_query` witness the answerer and the order it places on a session
//! bundle. What neither can say is that the verb is HOSTED: that a node started
//! with `--session-lifecycle --session-close-permit` registers the two queryables,
//! that a query from another process reaches them, that the verdict comes back
//! over the session, and that the session it names actually goes down. This does.
//!
//! Topology (all `wz-ap-demo`, no foreign binary):
//!   * peer A, `--peer`, zid pinned, hosting the lifecycle queries with the permit;
//!   * peer D, `--peer --connect A`, zid pinned: the session A is asked to close;
//!   * clients Q1, Q2, ... : one `--connect A --query <key>` each, whose reply log
//!     is the answer.
//!
//! The zids are pinned because the close key names the peer by zid, and a random
//! zid (R2883) could not be put in a key before the peer exists.
//!
//! The effect is asserted, not only the verdict: A logs `face N DOWN` for the face
//! D's session held. A verdict of `closing` over a session that stayed up would be
//! the worst answer the verb could give.
//!
//! A SECOND test hosts the queries WITHOUT the permit and asks for a close: the
//! answer is `refused` with a reason, and no session is needed for that, because
//! the authority speaks before the directory is read.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    ChildGuard, PortReservation,
};

const A_ZID: &str = "aa11aa11aa11aa11";
const D_ZID: &str = "dd22dd22dd22dd22";

/// The demo, checked to be newer than the sources it was built from: this test
/// needs the demo ALIVE and answering the queries, so a stale binary that predates
/// them would read as a node that never hosted them.
fn demo_binary() -> std::path::PathBuf {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    demo
}

/// A spawned `wz-ap-demo` whose stderr is captured to a file.
struct Node {
    guard: ChildGuard,
    log: File,
}

fn spawn(label: &str, args: &[&str]) -> Node {
    let stderr = tempfile::tempfile().expect("tempfile for stderr");
    let writer = stderr.try_clone().expect("dup stderr handle");
    let guard = ChildGuard::wrap(
        label,
        Command::new(demo_binary())
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
    );
    Node { guard, log: stderr }
}

impl Node {
    fn wait_for(&mut self, needle: &str, secs: u64) -> Result<String, String> {
        wait_for_substring(&mut self.log, needle, Duration::from_secs(secs))
    }

    fn stop(&mut self) -> String {
        let _ = self.guard.child_mut().kill();
        let _ = self.guard.child_mut().wait();
        read_captured(&mut self.log)
    }
}

/// Ask `node_addr` the query `key` from a fresh client and return the client's
/// reply log, or panic with both sides' logs if no reply came.
fn ask(node_addr: &str, key: &str, node: &mut Node) -> String {
    let mut client = spawn(
        "wz-ap-demo client (--connect --query --on-query-reply-log)",
        &[
            "--connect",
            node_addr,
            "--query",
            key,
            "--on-query-reply-log",
        ],
    );
    let reply = client.wait_for("REPLY RECEIVED", 10);
    let client_log = client.stop();
    match reply {
        Ok(captured) => captured,
        Err(_) => panic!(
            "no 'REPLY RECEIVED' for {key} within 10s\n--- client ---\n{client_log}\n--- node ---\n{}",
            read_captured(&mut node.log)
        ),
    }
}

/// The face id the peer at `zid_hex` holds on `node`, read off its `face N UP`
/// line (the line prints the peer's zid in wire order, so the match is on the role
/// the line also prints: the peer D is the only `Peer` this node accepts).
fn peer_face(log: &str) -> u64 {
    log.lines()
        .find(|l| l.contains(" UP (peer ") && l.contains("whatami Some(Peer)"))
        .and_then(|l| {
            l.split_once("face ")?
                .1
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no 'face N UP' line for a Peer in:\n{log}"))
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,session-close-ingress); Layer E6 runs via --ignored"]
fn wz_peer_session_lifecycle_close_query_closes_the_session_and_answers() {
    let (port_res, port_d) = PortReservation::pick_pair();
    let addr_a = format!("127.0.0.1:{}", port_res.port());
    let addr_d = format!("127.0.0.1:{port_d}");

    let mut a = spawn(
        "wz-ap-demo peer A (--peer --session-lifecycle --session-close-permit)",
        &[
            "--peer",
            &addr_a,
            "--zid",
            A_ZID,
            "--session-lifecycle",
            "--session-close-permit",
        ],
    );
    let verbs_key = format!("@/{A_ZID}/peer/session/verbs");
    if let Err(captured) = a.wait_for(&format!("session lifecycle query at {verbs_key}"), 5) {
        panic!(
            "peer A did not host the lifecycle queries (is the demo built with \
             --features routing-peer,session-close-ingress?)\n--- A ---\n{captured}"
        );
    }
    drop(port_res);

    let mut d = spawn(
        "wz-ap-demo peer D (--peer --connect A)",
        &["--peer", &addr_d, "--zid", D_ZID, "--connect", &addr_a],
    );
    let a_up = a
        .wait_for(" UP (peer ", 10)
        .unwrap_or_else(|c| panic!("A never accepted peer D\n--- A ---\n{c}"));
    let face = peer_face(&a_up);

    // CAPABILITY: the node says which verbs it has.
    let verbs = ask(&addr_a, &verbs_key, &mut a);
    assert!(
        verbs.contains(r#"\"verbs\":[\"close\",\"reset\",\"status\"]"#),
        "the capability query did not list the close, reset and status verbs:\n{verbs}"
    );

    // STATUS (decision D6): the session with D read over the wire, one link and no
    // close ordered; a peer holds nobody by a machine, so no machine is listed.
    let status = ask(
        &addr_a,
        &format!("@/{A_ZID}/peer/session/status/{D_ZID}"),
        &mut a,
    );
    assert!(
        status.contains(r#"\"links\":{\"open\":1,\"closing\":0}"#)
            && status.contains(r#"\"machines\":[]"#),
        "the status of a held session must read one open link:\n{status}"
    );

    // CLOSE: the verdict, then the effect.
    let close_key = format!("@/{A_ZID}/peer/session/close/{D_ZID}");
    let closing = ask(&addr_a, &close_key, &mut a);
    assert!(
        closing.contains(r#"\"verdict\":\"closing\""#) && closing.contains(r#"\"links\":1"#),
        "a permitted close of a held session must answer closing on 1 link:\n{closing}"
    );
    let down = a.wait_for(&format!("face {face} DOWN"), 10);
    let d_log = d.stop();
    let a_log = a.stop();
    down.unwrap_or_else(|_| {
        panic!(
            "the verdict said closing and A's face {face} never went DOWN\n--- A ---\n{a_log}\n--- D ---\n{d_log}"
        )
    });
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,session-close-ingress); Layer E6 runs via --ignored"]
fn wz_peer_session_lifecycle_close_without_the_permit_is_refused_with_a_reason() {
    let port_res = PortReservation::pick();
    let addr_a = format!("127.0.0.1:{}", port_res.port());

    let mut a = spawn(
        "wz-ap-demo peer A (--peer --session-lifecycle, no permit)",
        &["--peer", &addr_a, "--zid", A_ZID, "--session-lifecycle"],
    );
    let verbs_key = format!("@/{A_ZID}/peer/session/verbs");
    if let Err(captured) = a.wait_for(&format!("session lifecycle query at {verbs_key}"), 5) {
        panic!("peer A did not host the lifecycle queries\n--- A ---\n{captured}");
    }
    drop(port_res);

    // The node knows the verb whether or not it permits it...
    let verbs = ask(&addr_a, &verbs_key, &mut a);
    assert!(
        verbs.contains(r#"\"verbs\":[\"close\",\"reset\",\"status\"]"#),
        "the capability query is about the node's verbs, not the permit:\n{verbs}"
    );
    // ...and refuses to run it, saying why, before it reads any session.
    let close_key = format!("@/{A_ZID}/peer/session/close/{D_ZID}");
    let refused = ask(&addr_a, &close_key, &mut a);
    assert!(
        refused.contains(r#"\"verdict\":\"refused\""#) && refused.contains(r#"\"reason\":\""#),
        "an unpermitted close must answer refused with a reason:\n{refused}"
    );
    let _ = a.stop();
}
